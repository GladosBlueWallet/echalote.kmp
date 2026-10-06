package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.atomics.update

@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class Emitter<T> {
    private val listeners = kotlin.concurrent.atomics.AtomicReference(emptyList<(T) -> Unit>())
    private val lock = SpinLock()
    private val pending = ArrayList<CompletableDeferred<T>>()
    private var failure: Throwable? = null

    fun on(fn: (T) -> Unit): () -> Unit {
        listeners.update { it + fn }
        return { drop(fn) }
    }

    fun emit(value: T) {
        val copy = lock.withLock { listeners.load() }
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
            listeners.update { it + listener }
        }
        return try {
            withAbort(abort) { done.await() }
        } finally {
            drop(listener)
            lock.withLock { pending.remove(done) }
        }
    }

    private fun drop(fn: (T) -> Unit) {
        listeners.update { current ->
            val index = current.indexOfFirst { it === fn }
            if (index < 0) current else current.filterIndexed { i, _ -> i != index }
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
    internal val windowWaiters = ArrayList<CompletableDeferred<Unit>>()
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
    internal val writeLock = Mutex()
    internal val dataLock = Mutex()
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
        with(TorSend) {
            if (rcommand == RelayCmd.DATA) {
                this@SecretTorClientDuplex.sendData(circuit, streamId, fragment)
            } else {
                this@SecretTorClientDuplex.writeRelay(
                    TorSend.RelayWrite(circuit, rcommand, streamId, fragment, early),
                )
            }
        }
    }

    fun close() {
        if (closed != null) return
        closed = true
        val reason = Exception("tor connection closed")
        with(TorSend) { this@SecretTorClientDuplex.failWaits(reason) }
        closeEvent.emit(Unit)
        job.cancel()
        tls.close()
    }

    fun error(reason: Throwable) {
        if (closed != null) return
        closed = reason
        with(TorSend) { this@SecretTorClientDuplex.failWaits(reason) }
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
        with(TorInbound) {
            when (relay.rcommand) {
                RelayCmd.EXTENDED2 -> this@SecretTorClientDuplex.onExtended(circ, relay)
                RelayCmd.CONNECTED -> this@SecretTorClientDuplex.onConnected(circ, relay)
                RelayCmd.DATA -> this@SecretTorClientDuplex.onData(circ, relay)
                RelayCmd.END -> this@SecretTorClientDuplex.onEnd(circ, relay)
                RelayCmd.TRUNCATED -> this@SecretTorClientDuplex.onTruncated(circ, relay)
                RelayCmd.SENDME -> this@SecretTorClientDuplex.onSendme(circ, relay)
                else -> Unit
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
        var opened = false
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
            opened = true
            return LiveCircuit(circuit)
        } finally {
            if (!opened) circuit.close()
        }
    }
}

private object TorSend {
    suspend fun SecretTorClientDuplex.sendData(
        circuit: SecretCircuit,
        streamId: Int,
        fragment: ByteArray,
    ) {
        while (true) {
            val waiter = parkUntilWindow(circuit, streamId)
            if (waiter == null) {
                val sent = writeDataIfOpen(circuit, streamId, fragment)
                if (sent) return
            } else {
                try {
                    waiter.await()
                } finally {
                    gate.withLock { windowWaiters.remove(waiter) }
                }
            }
        }
    }

    fun SecretTorClientDuplex.parkUntilWindow(
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

    fun SecretTorClientDuplex.dataWindowOpen(
        circuit: SecretCircuit,
        streamId: Int,
    ): Boolean {
        val reason =
            when {
                closed != null -> IllegalStateException("tor connection closed")
                circuit.closed != null -> (circuit.closed as? Throwable) ?: DestroyedError(0)
                circuit.streams[streamId] == null -> UnknownStreamError()
                circuit.targets.isEmpty() -> InvalidTorStateError()
                else -> null
            }
        if (reason != null) throw reason
        val stream = circuit.streams.getValue(streamId)
        val exit = circuit.targets.last()
        return stream.packageWindow > 0 && exit.packageWindow > 0
    }

    suspend fun SecretTorClientDuplex.writeDataIfOpen(
        circuit: SecretCircuit,
        streamId: Int,
        fragment: ByteArray,
    ): Boolean =
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
            if (record != null) {
                writeRelay(RelayWrite(circuit, RelayCmd.DATA, streamId, fragment, recordDigest = record))
            }
            record != null
        }

    class RelayWrite(
        val circuit: SecretCircuit,
        val rcommand: Int,
        val streamId: Int,
        val fragment: ByteArray,
        val early: Boolean = false,
        val recordDigest: Boolean = false,
    )

    suspend fun SecretTorClientDuplex.writeRelay(out: RelayWrite) {
        writeLock.withLock {
            val targets = gate.withLock { out.circuit.targets.toList() }
            val (payload, digest) =
                encodeRelayPayload(out.rcommand, out.streamId, out.fragment, targets, out.recordDigest)
            if (digest != null) gate.withLock { targets.last().digests += digest }
            val cmd = if (out.early) CellCmd.RELAY_EARLY else CellCmd.RELAY
            tls.outer.write(writeCell(out.circuit.id, cmd, payload))
        }
    }

    fun SecretTorClientDuplex.failWaits(reason: Throwable) {
        if (!handshaked.isCompleted) handshaked.completeExceptionally(reason)
        createdFast.fail(reason)
        relayExtended2.fail(reason)
        relayConnected.fail(reason)
        wakeWindowWaiters()
    }
}

internal fun SecretTorClientDuplex.drainWindowWaiters(): List<CompletableDeferred<Unit>> {
    val copy = windowWaiters.toList()
    windowWaiters.clear()
    return copy
}

internal fun SecretTorClientDuplex.wakeWindowWaiters() {
    val waiters = gate.withLock { drainWindowWaiters() }
    for (w in waiters) w.complete(Unit)
}

private object TorInbound {
    suspend fun SecretTorClientDuplex.onExtended(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
        if (relay.fromEndpoint()) {
            relayExtended2.emit(circ to readExtended2(relay.fragment))
        } else {
            circ.onCloseOrError(InvalidRelayCellDigestError())
        }
    }

    suspend fun SecretTorClientDuplex.onConnected(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
        val stream = streamFor(circ, relay)
        if (!relay.fromEndpoint()) {
            circ.onCloseOrError(InvalidRelayCellDigestError())
        } else if (stream != null) {
            relayConnected.emit(circ to stream)
        }
    }

    suspend fun SecretTorClientDuplex.onData(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
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
        if (sendme != null) sendRelay(circ, RelayCmd.SENDME, 0, sendmeCircuitPayload(sendme))
        val stream = streamFor(circ, relay)
        if (stream != null) {
            stream.onIncomingData(relay.fragment)
            relayData.emit(circ to (stream to relay.fragment))
        }
    }

    suspend fun SecretTorClientDuplex.onEnd(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
        val stream = streamFor(circ, relay)
        if (relay.fromEndpoint() && stream != null) {
            val waiters =
                gate.withLock {
                    circ.streams.remove(stream.id)
                    drainWindowWaiters()
                }
            for (w in waiters) w.complete(Unit)
            relayEnd.emit(circ to (stream to readRelayEnd(relay.fragment)))
        }
    }

    suspend fun SecretTorClientDuplex.onTruncated(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
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

    suspend fun SecretTorClientDuplex.onSendme(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ) {
        val stream = streamFor(circ, relay)
        if (relay.streamId != 0) {
            if (relay.fromEndpoint() && stream != null) creditStream(stream)
            return
        }
        val (version, frag) = readSendmeCircuit(relay.fragment)
        if (version != 1 || frag.size != 20) throw InvalidRelaySendmeCellDigestError()
        creditCircuit(circ, relay.hop, frag.copyOf(20))
    }

    fun SecretTorClientDuplex.streamFor(
        circ: SecretCircuit,
        relay: DecodedRelay,
    ): SecretTorStreamDuplex? = if (relay.streamId == 0) null else gate.withLock { circ.streams[relay.streamId] }

    fun SecretTorClientDuplex.creditStream(stream: SecretTorStreamDuplex) {
        val waiters =
            gate.withLock {
                stream.packageWindow += 50
                drainWindowWaiters()
            }
        for (w in waiters) w.complete(Unit)
    }

    fun SecretTorClientDuplex.creditCircuit(
        circ: SecretCircuit,
        hop: Int,
        digest: ByteArray,
    ) {
        val waiters =
            gate.withLock {
                val target = circ.targets.getOrNull(hop)
                val expect = if (target != null && target.digests.isNotEmpty()) target.digests.removeAt(0) else null
                if (target == null || expect == null || !equalBytes(digest, expect)) {
                    throw InvalidRelaySendmeCellDigestError()
                }
                target.packageWindow += 100
                drainWindowWaiters()
            }
        for (w in waiters) w.complete(Unit)
    }
}
