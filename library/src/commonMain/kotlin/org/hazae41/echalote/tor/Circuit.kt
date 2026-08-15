package org.hazae41.echalote

open class Circuit(val id: Int) {
    open suspend fun close() {}
    open suspend fun extendOrThrow(microdesc: Microdesc, abort: Abort? = null) {}
    open suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean = true,
        abort: Abort? = null,
    ): TorStreamDuplex = throw Unimplemented()
}

internal class LiveCircuit(internal val secret: SecretCircuit) : Circuit(secret.id) {
    override suspend fun close() = secret.close()
    override suspend fun extendOrThrow(microdesc: Microdesc, abort: Abort?) =
        secret.extendOrThrow(microdesc, abort)
    override suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean,
        abort: Abort?,
    ): TorStreamDuplex = secret.openOrThrow(hostname, port, wait, abort)
}

internal class SecretCircuit(
    val id: Int,
    val tor: SecretTorClientDuplex,
) {
    val targets = ArrayList<Target>()
    val streams = LinkedHashMap<Int, SecretTorStreamDuplex>()
    private var nextStreamId = 1
    var closed: Any? = null

    fun onCloseOrError(reason: Any?) {
        if (closed != null) return
        closed = reason ?: true
        for (s in streams.values.toList()) s.fail(reason as? Throwable ?: DestroyedError(0))
        streams.clear()
        tor.circuits.remove(id)
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

    suspend fun extendOrThrow(microdesc: Microdesc, abort: Abort? = null) {
        if (closed != null) throw (closed as? Throwable) ?: DestroyedError(0)
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
        val (secret, publicX) = X25519.randomKeyPair()
        val request = NtorRequest(publicX, relayidRsa, ntorKey)
        val reqBytes = ByteArray(request.size())
        request.write(Cursor(reqBytes))
        val extend = extend2Payload(2, links, reqBytes)
        val payload = encodeRelayPayload(RelayCmd.EXTEND2, 0, extend, targets, early = true)
        tor.send(writeCell(id, CellCmd.RELAY_EARLY, payload))
        val respBytes = tor.relayExtended2.wait(abort) { it.first === this }.second
        val response = NtorResponse.read(Cursor(respBytes))
        val sharedXy = X25519.scalarMult(secret, response.publicY)
        val sharedXb = X25519.scalarMult(secret, ntorKey)
        val result = NtorResult.finalizeOrThrow(
            sharedXy, sharedXb, relayidRsa, ntorKey, publicX, response.publicY,
        )
        if (!equalBytes(response.auth, result.auth)) throw InvalidNtorAuthError()
        val target = Target(
            relayidRsa,
            Sha1.Hasher().update(result.forwardDigest),
            Sha1.Hasher().update(result.backwardDigest),
            Aes128Ctr128BEKey(Memory(result.forwardKey), Memory(ByteArray(16))),
            Aes128Ctr128BEKey(Memory(result.backwardKey), Memory(ByteArray(16))),
        )
        targets += target
    }

    suspend fun openOrThrow(
        hostname: String,
        port: Int,
        wait: Boolean = true,
        abort: Abort? = null,
    ): TorStreamDuplex {
        if (closed != null) throw (closed as? Throwable) ?: DestroyedError(0)
        val stream = SecretTorStreamDuplex("external", nextStreamId++, this)
        streams[stream.id] = stream
        val begin = beginPayload("$hostname:$port", beginFlagsPreferred())
        val payload = encodeRelayPayload(RelayCmd.BEGIN, stream.id, begin, targets, early = false)
        tor.send(writeCell(id, CellCmd.RELAY, payload))
        if (wait) stream.waitConnected(abort)
        return stream.asPublic {}
    }
}
