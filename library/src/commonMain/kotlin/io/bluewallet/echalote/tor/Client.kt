package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class Emitter<T> {
    private val lock = SpinLock()
    private val listeners = ArrayList<(T) -> Unit>()
    private val pending = ArrayList<CompletableDeferred<T>>()
    private var failure: Throwable? = null

    fun on(fn: (T) -> Unit): () -> Unit {
        lock.withLock { listeners += fn }
        return { lock.withLock { listeners.remove(fn) } }
    }

    fun emit(value: T) {
        val copy = lock.withLock { listeners.toList() }
        for (l in copy) {
            try {
                l(value)
            } catch (_: Throwable) {
            }
        }
    }

    fun fail(reason: Throwable) {
        val waiters =
            lock.withLock {
                if (failure == null) failure = reason
                val copy = pending.toList()
                pending.clear()
                copy
            }
        for (d in waiters) {
            if (!d.isCompleted) d.completeExceptionally(reason)
        }
    }

    suspend fun wait(
        abort: Abort?,
        pred: (T) -> Boolean = { true },
    ): T {
        val done = CompletableDeferred<T>()
        val listener: (T) -> Unit = { v ->
            if (pred(v) && !done.isCompleted) done.complete(v)
        }
        lock.withLock {
            failure?.let { throw it }
            pending += done
            listeners += listener
        }
        return try {
            withAbort(abort) { done.await() }
        } finally {
            lock.withLock {
                listeners.remove(listener)
                pending.remove(done)
            }
        }
    }
}

internal sealed class TorState {
    data object None : TorState()

    data object Versioned : TorState()

    data class Handshaking(
        val identity: ByteArray,
        val certs: TorCerts,
    ) : TorState()

    data class Handshaked(
        val identity: ByteArray,
        val certs: TorCerts,
    ) : TorState()
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
    val gate = SpinLock()
    private val windowWaiters = ArrayList<CompletableDeferred<Unit>>()
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
    private val dataLock = Mutex()
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

    suspend fun sendRelay(
        circuit: SecretCircuit,
        rcommand: Int,
        streamId: Int,
        fragment: ByteArray,
        early: Boolean = false,
    ) {
        if (rcommand == RelayCmd.DATA) {
            sendData(circuit, streamId, fragment, early)
        } else {
            writeRelay(circuit, rcommand, streamId, fragment, early, false)
        }
    }

    private suspend fun sendData(
        circuit: SecretCircuit,
        streamId: Int,
        fragment: ByteArray,
        early: Boolean,
    ) {
        while (true) {
            val waiter = parkUntilWindow(circuit, streamId)
            if (waiter != null) {
                try {
                    waiter.await()
                } finally {
                    gate.withLock { windowWaiters.remove(waiter) }
                }
                continue
            }
            val sent =
                dataLock.withLock {
                    val record =
                        gate.withLock {
                            if (!dataWindowOpen(circuit, streamId)) return@withLock null
                            val stream = circuit.streams.getValue(streamId)
                            val exit = circuit.targets.last()
                            val mark = exit.packageWindow % 100 == 1
                            stream.packageWindow--
                            exit.packageWindow--
                            mark
                        }
                    if (record == null) {
                        false
                    } else {
                        writeRelay(circuit, RelayCmd.DATA, streamId, fragment, early, record)
                        true
                    }
                }
            if (sent) return
        }
    }

    private fun parkUntilWindow(
        circuit: SecretCircuit,
        streamId: Int,
    ): CompletableDeferred<Unit>? =
        gate.withLock {
            if (dataWindowOpen(circuit, streamId)) {
                null
            } else {
                CompletableDeferred<Unit>().also { windowWaiters += it }
            }
        }

    private fun dataWindowOpen(
        circuit: SecretCircuit,
        streamId: Int,
    ): Boolean {
        if (closed != null) throw Exception("tor connection closed")
        if (circuit.closed != null) throw (circuit.closed as? Throwable) ?: DestroyedError(0)
        val stream = circuit.streams[streamId] ?: throw UnknownStreamError()
        val exit = circuit.targets.lastOrNull() ?: throw InvalidTorStateError()
        return stream.packageWindow > 0 && exit.packageWindow > 0
    }

    private suspend fun writeRelay(
        circuit: SecretCircuit,
        rcommand: Int,
        streamId: Int,
        fragment: ByteArray,
        early: Boolean,
        recordDigest: Boolean,
    ) {
        writeLock.withLock {
            val targets = gate.withLock { circuit.targets.toList() }
            val (payload, digest) =
                encodeRelayPayload(rcommand, streamId, fragment, targets, early, recordDigest)
            if (digest != null) {
                gate.withLock { targets.last().digests += digest }
            }
            val cmd = if (early) CellCmd.RELAY_EARLY else CellCmd.RELAY
            tls.outer.write(writeCell(circuit.id, cmd, payload))
        }
    }

    internal fun drainWindowWaiters(): List<CompletableDeferred<Unit>> {
        val copy = windowWaiters.toList()
        windowWaiters.clear()
        return copy
    }

    internal fun wakeWindowWaiters() {
        val waiters = gate.withLock { drainWindowWaiters() }
        for (w in waiters) w.complete(Unit)
    }

    private fun failWaits(reason: Throwable) {
        if (!handshaked.isCompleted) handshaked.completeExceptionally(reason)
        createdFast.fail(reason)
        relayExtended2.fail(reason)
        relayConnected.fail(reason)
        wakeWindowWaiters()
    }

    fun close() {
        if (closed != null) return
        closed = true
        val reason = Exception("tor connection closed")
        failWaits(reason)
        closeEvent.emit(Unit)
        job.cancel()
        tls.close()
    }

    fun error(reason: Throwable) {
        if (closed != null) return
        closed = reason
        failWaits(reason)
        errorEvent.emit(reason)
        job.cancel()
        tls.close()
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
                val circ = if (cell.circuitId != 0) gate.withLock { circuits[cell.circuitId] } else null
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
                        try {
                            val hops = gate.withLock { circ.targets.toList() }
                            onRelay(circ, decodeRelayPayload(cell.payload, hops))
                        } catch (e: kotlinx.coroutines.CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            circ.onCloseOrError(e)
                        }
                    }
                }
            }
        }
    }

    private suspend fun onRelay(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
        val stream =
            if (relay.streamId != 0) gate.withLock { circ.streams[relay.streamId] } else null
        when (relay.rcommand) {
            RelayCmd.EXTENDED2 -> {
                if (!relay.fromEndpoint()) {
                    circ.onCloseOrError(InvalidRelayCellDigestError())
                    return
                }
                relayExtended2.emit(circ to readExtended2(relay.fragment))
            }
            RelayCmd.CONNECTED -> {
                if (!relay.fromEndpoint()) {
                    circ.onCloseOrError(InvalidRelayCellDigestError())
                    return
                }
                if (stream != null) relayConnected.emit(circ to stream)
            }
            RelayCmd.DATA -> {
                if (!relay.fromEndpoint()) {
                    circ.onCloseOrError(InvalidRelayCellDigestError())
                    return
                }
                val sendme =
                    gate.withLock {
                        val exit = circ.targets.getOrNull(relay.hop) ?: return@withLock null
                        exit.delivery--
                        if (exit.delivery == 900) {
                            exit.delivery = 1000
                            relay.digest20
                        } else {
                            null
                        }
                    }
                if (sendme != null) {
                    sendRelay(circ, RelayCmd.SENDME, 0, sendmeCircuitPayload(sendme))
                }
                if (stream != null) {
                    stream.onIncomingData(relay.fragment)
                    relayData.emit(circ to (stream to relay.fragment))
                }
            }
            RelayCmd.END -> {
                if (!relay.fromEndpoint() || stream == null) return
                val waiters =
                    gate.withLock {
                        circ.streams.remove(stream.id)
                        drainWindowWaiters()
                    }
                for (w in waiters) w.complete(Unit)
                relayEnd.emit(circ to (stream to readRelayEnd(relay.fragment)))
            }
            RelayCmd.DROP -> {}
            RelayCmd.TRUNCATED -> {
                if (!relay.fromEndpoint()) {
                    circ.onCloseOrError(InvalidRelayCellDigestError())
                    return
                }
                gate.withLock {
                    if (circ.targets.isNotEmpty()) circ.targets.removeLast()
                }
                val reason = if (relay.fragment.isNotEmpty()) relay.fragment.u8(0) else 0
                relayTruncated.emit(circ to reason)
            }
            RelayCmd.SENDME -> {
                if (relay.streamId != 0) {
                    if (!relay.fromEndpoint() || stream == null) return
                    val waiters =
                        gate.withLock {
                            stream.packageWindow += 50
                            drainWindowWaiters()
                        }
                    for (w in waiters) w.complete(Unit)
                    return
                }
                val (version, frag) = readSendmeCircuit(relay.fragment)
                if (version != 1 || frag.size != 20) throw InvalidRelaySendmeCellDigestError()
                val digest = frag.copyOf(20)
                val waiters =
                    gate.withLock {
                        val hop = circ.targets.getOrNull(relay.hop) ?: throw InvalidRelaySendmeCellDigestError()
                        val expect = if (hop.digests.isNotEmpty()) hop.digests.removeAt(0) else null
                        if (expect == null || !equalBytes(digest, expect)) throw InvalidRelaySendmeCellDigestError()
                        hop.packageWindow += 100
                        drainWindowWaiters()
                    }
                for (w in waiters) w.complete(Unit)
            }
        }
    }

    suspend fun createOrThrow(abort: Abort? = null): Circuit {
        waitOrThrow(abort)
        val st = state as? TorState.Handshaked ?: throw InvalidTorStateError()
        val circuit =
            gate.withLock {
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
        try {
            val material = secureRandom(20)
            send(writeCell(circuit.id, CellCmd.CREATE_FAST, createFastPayload(material)))
            val created = createdFast.wait(abort) { it.first === circuit }
            val k0 = concatBytes(material, created.second.first)
            val result = KDFTorResult.computeOrThrow(k0)
            if (!equalBytes(result.keyHash, created.second.second)) throw InvalidKdfKeyHashError()
            val forwardDigest = Sha1.Hasher().update(result.forwardDigest)
            val backwardDigest = Sha1.Hasher().update(result.backwardDigest)
            val target =
                Target(
                    st.identity,
                    forwardDigest,
                    backwardDigest,
                    Aes128Ctr128BEKey(Memory(result.forwardKey), Memory(ByteArray(16))),
                    Aes128Ctr128BEKey(Memory(result.backwardKey), Memory(ByteArray(16))),
                )
            gate.withLock { circuit.targets += target }
            return LiveCircuit(circuit)
        } catch (err: Throwable) {
            try {
                circuit.close()
            } catch (_: Throwable) {
            }
            throw err
        }
    }
}
