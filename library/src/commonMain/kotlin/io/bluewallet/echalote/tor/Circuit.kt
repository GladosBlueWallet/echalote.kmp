package io.bluewallet.echalote

open class Circuit(
    val id: Int,
) {
    open val isClosed: Boolean get() = false

    open suspend fun close() {}

    open suspend fun extendOrThrow(
        microdesc: Microdesc,
        abort: Abort? = null,
    ) {}

    open suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean = true,
        abort: Abort? = null,
    ): TorStreamDuplex = throw Unimplemented()
}

internal class LiveCircuit(
    internal val secret: SecretCircuit,
) : Circuit(secret.id) {
    override val isClosed: Boolean get() = secret.closed != null

    override suspend fun close() = secret.close()

    override suspend fun extendOrThrow(
        microdesc: Microdesc,
        abort: Abort?,
    ) = secret.extendOrThrow(microdesc, abort)

    override suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean,
        abort: Abort?,
    ): TorStreamDuplex = secret.openOrThrow(hostname, port, wait, abort)
}

internal fun nextClientStreamId(previous: Int): Int {
    val next = if (previous <= 0) 1 else previous + 2
    if (next > 0xffff) error("tor stream id space exhausted")
    return next
}

internal class SecretCircuit(
    val id: Int,
    val tor: SecretTorClientDuplex,
) {
    val targets = ArrayList<Target>()
    val streams = LinkedHashMap<Int, SecretTorStreamDuplex>()
    private var lastStreamId = 0
    var closed: Any? = null

    fun onCloseOrError(reason: Any?) {
        val doomed =
            tor.gate.withLock {
                if (closed != null) {
                    null
                } else {
                    closed = reason ?: true
                    val list = streams.values.toList()
                    streams.clear()
                    tor.circuits.remove(id)
                    list to tor.drainWindowWaiters()
                }
            } ?: return
        for (w in doomed.second) w.complete(Unit)
        val err = reason as? Throwable ?: DestroyedError(0)
        for (s in doomed.first) s.fail(err)
    }

    suspend fun close(reason: Int = DestroyReasons.NONE) {
        val error = DestroyedError(reason)
        if (tor.closed == null) {
            try {
                tor.send(writeCell(id, CellCmd.DESTROY, destroyPayload(reason)))
            } catch (_: Throwable) {
            }
        }
        onCloseOrError(error)
    }

    private fun throwIfClosed() {
        if (closed != null) throw (closed as? Throwable) ?: DestroyedError(0)
    }

    suspend fun extendOrThrow(
        microdesc: Microdesc,
        abort: Abort? = null,
    ) {
        throwIfClosed()
        val relayidRsa = Base64.decode(microdesc.identity)
        require(relayidRsa.size == HASH_LEN) { "bad identity" }
        val ntorKey = Base64.decode(microdesc.ntorOnionKey)
        require(ntorKey.size == 32) { "bad ntor key" }
        val relayidEd = microdesc.idEd25519.takeIf { it.isNotEmpty() }?.let { Base64.decode(it) }
        val links = ArrayList<ByteArray>()
        links += extend2LinkIpv4(microdesc.hostname, microdesc.orport)
        microdesc.ipv6?.let { links += extend2LinkIpv6(it) }
        links += extend2LinkLegacyId(relayidRsa)
        if (relayidEd != null) links += extend2LinkModernId(relayidEd)
        tor.gate.withLock { throwIfClosed() }
        val (secret, publicX) = X25519.randomKeyPair()
        val request = NtorRequest(publicX, relayidRsa, ntorKey)
        val reqBytes = ByteArray(request.size())
        request.write(Cursor(reqBytes))
        val extend = extend2Payload(2, links, reqBytes)
        tor.sendRelay(this, RelayCmd.EXTEND2, 0, extend, early = true)
        val respBytes = tor.relayExtended2.wait(abort) { it.first === this }.second
        val response = NtorResponse.read(Cursor(respBytes))
        val sharedXy = X25519.scalarMult(secret, response.publicY)
        val sharedXb = X25519.scalarMult(secret, ntorKey)
        val result =
            NtorResult.finalizeOrThrow(
                sharedXy,
                sharedXb,
                relayidRsa,
                ntorKey,
                publicX,
                response.publicY,
            )
        if (!equalBytes(response.auth, result.auth)) throw InvalidNtorAuthError()
        val target =
            Target(
                relayidRsa,
                Sha1.Hasher().update(result.forwardDigest),
                Sha1.Hasher().update(result.backwardDigest),
                Aes128Ctr128BEKey(Memory(result.forwardKey), Memory(ByteArray(16))),
                Aes128Ctr128BEKey(Memory(result.backwardKey), Memory(ByteArray(16))),
            )
        tor.gate.withLock {
            throwIfClosed()
            targets += target
        }
    }

    suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean = true,
        abort: Abort? = null,
    ): TorStreamDuplex {
        val stream =
            tor.gate.withLock {
                throwIfClosed()
                lastStreamId = nextClientStreamId(lastStreamId)
                val created = SecretTorStreamDuplex("external", lastStreamId, this)
                streams[created.id] = created
                created
            }
        val begin = beginPayload("$hostname:$port", beginFlagsPreferred())
        tor.sendRelay(this, RelayCmd.BEGIN, stream.id, begin)
        if (wait) stream.waitConnected(abort)
        return stream.asPublic {}
    }
}
