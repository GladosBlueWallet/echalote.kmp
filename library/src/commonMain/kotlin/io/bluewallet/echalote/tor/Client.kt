package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class Emitter<T> {
    private val lock = Mutex()
    private val listeners = ArrayList<(T) -> Unit>()

    fun on(fn: (T) -> Unit): () -> Unit {
        listeners += fn
        return {
            listeners.remove(fn)
        }
    }

    fun emit(value: T) {
        for (l in listeners.toList()) {
            try {
                l(value)
            } catch (_: Throwable) {
            }
        }
    }

    suspend fun wait(abort: Abort?, pred: (T) -> Boolean = { true }): T {
        val done = CompletableDeferred<T>()
        val off = on { v ->
            if (pred(v) && !done.isCompleted) done.complete(v)
        }
        return try {
            withAbort(abort) { done.await() }
        } finally {
            off()
        }
    }
}

internal sealed class TorState {
    data object None : TorState()
    data object Versioned : TorState()
    data class Handshaking(val identity: ByteArray, val certs: TorCerts) : TorState()
    data class Handshaked(val identity: ByteArray, val certs: TorCerts) : TorState()
}

open class TorClientDuplex {
    internal val secret = SecretTorClientDuplex()
    val inner: ByteDuplex get() = secret.inner
    var closed: Any? = null
        get() = secret.closed
        internal set

    open suspend fun waitOrThrow(abort: Abort? = null) = secret.waitOrThrow(abort)
    open suspend fun createOrThrow(abort: Abort? = null): Circuit = secret.createOrThrow(abort)
    open fun close() = secret.close()
}

internal class SecretTorClientDuplex {
    val tls = TlsClientDuplex()
    val inner: ByteDuplex get() = tls.inner
    val circuits = LinkedHashMap<Int, SecretCircuit>()
    val circuitsLock = Mutex()
    var state: TorState = TorState.None
    var closed: Any? = null
    val createdFast = Emitter<Pair<SecretCircuit, Pair<ByteArray, ByteArray>>>()
    val destroyed = Emitter<Pair<SecretCircuit, Int>>()
    val relayExtended2 = Emitter<Pair<SecretCircuit, ByteArray>>()
    val relayTruncated = Emitter<Pair<SecretCircuit, Int>>()
    val relayConnected = Emitter<Pair<SecretCircuit, SecretTorStreamDuplex>>()
    val relayData = Emitter<Pair<SecretCircuit, Pair<SecretTorStreamDuplex, ByteArray>>>()
    val relayEnd = Emitter<Pair<SecretCircuit, Pair<SecretTorStreamDuplex, RelayEndReason>>>()
    val handshaked = CompletableDeferred<Unit>()
    val closeEvent = Emitter<Unit>()
    val errorEvent = Emitter<Throwable>()
    private val writeLock = Mutex()
    private val job = SupervisorJob()
    internal val scope = CoroutineScope(job + Dispatchers.Default)

    init {
        scope.launch {
            try {
                send(writeOldCell(0, CellCmd.VERSIONS, versionsPayload(intArrayOf(5))))
                readLoop()
            } catch (e: Throwable) {
                error(e)
            }
        }
    }

    suspend fun send(bytes: ByteArray) {
        writeLock.withLock { tls.outer.write(bytes) }
    }

    fun close() {
        if (closed != null) return
        closed = true
        job.cancel()
        tls.close()
        closeEvent.emit(Unit)
    }

    fun error(reason: Throwable) {
        if (closed != null) return
        closed = reason
        job.cancel()
        tls.close()
        errorEvent.emit(reason)
        handshaked.completeExceptionally(reason)
    }

    suspend fun waitOrThrow(abort: Abort? = null) {
        if (state is TorState.Handshaked) return
        withAbort(abort) { handshaked.await() }
    }

    private suspend fun readLoop() {
        var buf = ByteArray(0)
        while (closed == null) {
            val chunk = tls.outer.read(16 * 1024)
            if (chunk.isEmpty()) {
                close()
                return
            }
            buf = concatBytes(buf, chunk)
            val cursor = Cursor(buf)
            while (cursor.remaining > 0) {
                val mark = cursor.offset
                val cell = if (state is TorState.None) tryReadOldCell(cursor) else tryReadCell(cursor)
                if (cell == null) {
                    cursor.offset = mark
                    break
                }
                onCell(cell)
            }
            buf = if (cursor.remaining > 0) buf.copyOfRange(cursor.offset, buf.size) else ByteArray(0)
        }
    }

    private suspend fun onCell(cell: RawCell) {
        if (cell.command == CellCmd.PADDING || cell.command == CellCmd.VPADDING) return
        when (val s = state) {
            is TorState.None -> {
                if (cell.command == CellCmd.VERSIONS) {
                    val versions = readVersions(cell.payload)
                    if (5 !in versions.toList()) throw InvalidTorVersionError()
                    state = TorState.Versioned
                }
            }
            is TorState.Versioned -> {
                if (cell.command == CellCmd.CERTS) {
                    val tlsDer = tls.leafCertDer.await()
                    val parsed = parseCertsCell(cell.payload)
                    val certs = verifyTorCerts(parsed, tlsDer)
                    val identity = certs.rsaSelf.sha1OrThrow()
                    state = TorState.Handshaking(identity, certs)
                }
            }
            is TorState.Handshaking -> {
                if (cell.command == CellCmd.AUTH_CHALLENGE) return
                if (cell.command == CellCmd.NETINFO) {
                    send(writeCell(0, CellCmd.NETINFO, netinfoPayload()))
                    send(writeCell(0, CellCmd.PADDING_NEGOTIATE, paddingNegotiateStop()))
                    state = TorState.Handshaked(s.identity, s.certs)
                    handshaked.complete(Unit)
                }
            }
            is TorState.Handshaked -> {
                val circ = if (cell.circuitId != 0) circuits[cell.circuitId] else null
                when (cell.command) {
                    CellCmd.CREATED_FAST -> {
                        if (circ != null) createdFast.emit(circ to readCreatedFast(cell.payload))
                    }
                    CellCmd.DESTROY -> {
                        if (circ != null) {
                            val reason = readDestroy(cell.payload)
                            circ.onCloseOrError(DestroyedError(reason))
                            destroyed.emit(circ to reason)
                        }
                    }
                    CellCmd.RELAY -> {
                        if (circ == null) return
                        val relay = decodeRelayPayload(cell.payload, circ.targets)
                        onRelay(circ, relay)
                    }
                }
            }
        }
    }

    private suspend fun onRelay(circ: SecretCircuit, relay: DecodedRelay) {
        val stream = if (relay.streamId != 0) circ.streams[relay.streamId] else null
        when (relay.rcommand) {
            RelayCmd.EXTENDED2 -> relayExtended2.emit(circ to readExtended2(relay.fragment))
            RelayCmd.CONNECTED -> if (stream != null) relayConnected.emit(circ to stream)
            RelayCmd.DATA -> {
                if (stream == null) return
                val exit = circ.targets.last()
                exit.delivery--
                if (exit.delivery == 900) {
                    exit.delivery = 1000
                    val sendme = sendmeCircuitPayload(relay.digest20)
                    val payload = encodeRelayPayload(RelayCmd.SENDME, 0, sendme, circ.targets, early = false)
                    send(writeCell(circ.id, CellCmd.RELAY, payload))
                }
                stream.onIncomingData(relay.fragment)
                relayData.emit(circ to (stream to relay.fragment))
            }
            RelayCmd.END -> if (stream != null) {
                circ.streams.remove(stream.id)
                relayEnd.emit(circ to (stream to readRelayEnd(relay.fragment)))
            }
            RelayCmd.DROP -> {}
            RelayCmd.TRUNCATED -> {
                if (circ.targets.isNotEmpty()) circ.targets.removeLast()
                val reason = if (relay.fragment.isNotEmpty()) relay.fragment.u8(0) else 0
                relayTruncated.emit(circ to reason)
            }
            RelayCmd.SENDME -> {
                if (stream == null) {
                    val (version, frag) = readSendmeCircuit(relay.fragment)
                    val exit = circ.targets.last()
                    if (version == 0) {
                        exit.packageWindow += 100
                    } else if (version == 1) {
                        val digest = Cursor(frag).read(20)
                        val expect = if (exit.digests.isNotEmpty()) exit.digests.removeAt(0) else null
                        if (expect == null || !equalBytes(digest, expect)) throw InvalidRelaySendmeCellDigestError()
                        exit.packageWindow += 100
                    }
                } else {
                    stream.packageWindow += 50
                }
            }
        }
    }

    suspend fun createOrThrow(abort: Abort? = null): Circuit {
        waitOrThrow(abort)
        val st = state as? TorState.Handshaked ?: throw InvalidTorStateError()
        val circuit = circuitsLock.withLock {
            var id = 0
            do {
                abort?.throwIfAborted()
                val raw = Cursor(secureRandom(4)).readU32()
                if (raw == 0) continue
                id = raw or Int.MIN_VALUE
            } while (id == 0 || circuits.containsKey(id))
            val secret = SecretCircuit(id, this)
            circuits[id] = secret
            secret
        }
        val material = secureRandom(20)
        send(writeCell(circuit.id, CellCmd.CREATE_FAST, createFastPayload(material)))
        val created = createdFast.wait(abort) { it.first === circuit }
        val k0 = concatBytes(material, created.second.first)
        val result = KDFTorResult.computeOrThrow(k0)
        if (!equalBytes(result.keyHash, created.second.second)) throw InvalidKdfKeyHashError()
        val forwardDigest = Sha1.Hasher().update(result.forwardDigest)
        val backwardDigest = Sha1.Hasher().update(result.backwardDigest)
        val target = Target(
            st.identity,
            forwardDigest,
            backwardDigest,
            Aes128Ctr128BEKey(Memory(result.forwardKey), Memory(ByteArray(16))),
            Aes128Ctr128BEKey(Memory(result.backwardKey), Memory(ByteArray(16))),
        )
        circuit.targets += target
        return LiveCircuit(circuit)
    }
}
