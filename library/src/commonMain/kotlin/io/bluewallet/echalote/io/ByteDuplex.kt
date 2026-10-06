package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred

interface ByteDuplex {
    /** Return 1..n bytes, or an empty array at EOF. */
    suspend fun read(n: Int): ByteArray

    suspend fun write(bytes: ByteArray)

    fun close()
}

private class DuplexSide {
    val inbox = ArrayDeque<ByteArray>()
    var closed = false
    var peerClosed = false
    var waiter: Waiter? = null
    val lock = SpinLock()
}

private class Waiter(
    val n: Int,
    val deferred: CompletableDeferred<ByteArray>,
)

private class Ready(
    val deferred: CompletableDeferred<ByteArray>,
    val chunk: ByteArray,
)

private fun take(
    state: DuplexSide,
    n: Int,
): ByteArray? {
    val chunk = state.inbox.firstOrNull() ?: return null
    return if (chunk.size <= n) {
        state.inbox.removeFirst()
        chunk
    } else {
        val result = chunk.copyOf(n)
        state.inbox[0] = chunk.copyOfRange(n, chunk.size)
        result
    }
}

private fun ready(state: DuplexSide): Ready? {
    val waiter = state.waiter
    val chunk = if (waiter != null) take(state, waiter.n) else null
    val done = chunk != null || (waiter != null && (state.closed || state.peerClosed))
    if (done && waiter != null) state.waiter = null
    return if (done && waiter != null) Ready(waiter.deferred, chunk ?: ByteArray(0)) else null
}

private fun deliver(
    inbox: ArrayDeque<ByteArray>,
    lock: SpinLock,
    ready: Ready?,
    wake: () -> Ready?,
) {
    var pending = ready
    while (pending != null) {
        val current = pending
        if (current.deferred.complete(current.chunk) || current.chunk.isEmpty()) return
        pending =
            lock.withLock {
                inbox.addFirst(current.chunk)
                wake()
            }
    }
}

fun pairedByteDuplexes(): Pair<ByteDuplex, ByteDuplex> {
    val leftState = DuplexSide()
    val rightState = DuplexSide()

    fun make(
        state: DuplexSide,
        peer: DuplexSide,
    ): ByteDuplex =
        object : ByteDuplex {
            override suspend fun read(n: Int): ByteArray {
                val deferred =
                    state.lock.withLock {
                        val chunk = take(state, n)
                        if (chunk != null) return@withLock Completed(chunk)
                        if (state.closed || state.peerClosed) return@withLock Completed(ByteArray(0))
                        check(state.waiter == null) { "concurrent reads are not supported" }
                        val waiter = Waiter(n, CompletableDeferred())
                        state.waiter = waiter
                        Parked(waiter.deferred)
                    }
                return when (deferred) {
                    is Completed -> deferred.bytes
                    is Parked ->
                        try {
                            deferred.deferred.await()
                        } finally {
                            state.lock.withLock {
                                if (state.waiter?.deferred === deferred.deferred) state.waiter = null
                            }
                        }
                }
            }

            override suspend fun write(bytes: ByteArray) {
                val done =
                    peer.lock.withLock {
                        check(!state.closed && !peer.closed) { "cannot write to closed duplex" }
                        peer.inbox.addLast(bytes.copyOf())
                        ready(peer)
                    }
                deliver(peer.inbox, peer.lock, done) { ready(peer) }
            }

            override fun close() {
                val local =
                    state.lock.withLock {
                        state.closed = true
                        ready(state)
                    }
                val remote =
                    peer.lock.withLock {
                        peer.peerClosed = true
                        ready(peer)
                    }
                deliver(state.inbox, state.lock, local) { ready(state) }
                deliver(peer.inbox, peer.lock, remote) { ready(peer) }
            }
        }

    return make(leftState, rightState) to make(rightState, leftState)
}

private sealed interface ReadSlot

private class Completed(
    val bytes: ByteArray,
) : ReadSlot

private class Parked(
    val deferred: CompletableDeferred<ByteArray>,
) : ReadSlot

internal suspend fun ByteDuplex.readExact(n: Int): ByteArray {
    if (n == 0) return ByteArray(0)
    val out = ByteArray(n)
    var off = 0
    while (off < n) {
        val chunk = read(n - off)
        check(chunk.isNotEmpty()) { "unexpected EOF" }
        chunk.copyInto(out, off)
        off += chunk.size
    }
    return out
}

internal suspend fun pipeDuplex(
    src: ByteDuplex,
    dst: ByteDuplex,
) {
    try {
        while (true) {
            val chunk = src.read(16 * 1024)
            if (chunk.isEmpty()) break
            dst.write(chunk)
        }
    } catch (_: Throwable) {
    } finally {
        try {
            dst.close()
        } catch (_: Throwable) {
        }
    }
}

class ChannelDuplex : ByteDuplex {
    private val lock = SpinLock()
    private val inbox = ArrayDeque<ByteArray>()
    private var closed = false
    private var terminal: Throwable? = null
    private var waiter: Waiter? = null
    var onWrite: (suspend (ByteArray) -> Unit)? = null
    var onClose: (() -> Unit)? = null
    var onRead: ((Int) -> Unit)? = null

    private fun take(n: Int): ByteArray? {
        val chunk = inbox.firstOrNull() ?: return null
        return if (chunk.size <= n) {
            inbox.removeFirst()
            chunk
        } else {
            val result = chunk.copyOf(n)
            inbox[0] = chunk.copyOfRange(n, chunk.size)
            result
        }
    }

    private fun ready(): Ready? {
        val w = waiter
        val chunk = if (w != null) take(w.n) else null
        val done = chunk != null || (w != null && (terminal != null || closed))
        if (done) waiter = null
        return if (done && w != null) Ready(w.deferred, chunk ?: ByteArray(0)) else null
    }

    suspend fun enqueue(bytes: ByteArray) {
        val done =
            lock.withLock {
                if (closed) {
                    null
                } else {
                    inbox.addLast(bytes.copyOf())
                    ready()
                }
            }
        deliver(inbox, lock, done) { ready() }
    }

    fun error(reason: Throwable) {
        var pending =
            lock.withLock {
                terminal = reason
                closed = true
                ready()
            }
        while (pending != null) {
            val current = pending
            val delivered =
                if (current.chunk.isNotEmpty()) {
                    current.deferred.complete(current.chunk)
                } else {
                    current.deferred.completeExceptionally(reason)
                }
            if (delivered || current.chunk.isEmpty()) break
            pending =
                lock.withLock {
                    inbox.addFirst(current.chunk)
                    ready()
                }
        }
        onClose?.invoke()
    }

    override suspend fun read(n: Int): ByteArray {
        val slot =
            lock.withLock {
                val chunk = take(n)
                if (chunk != null) return@withLock Completed(chunk)
                if (inbox.isEmpty()) terminal?.let { throw it }
                if (closed) return@withLock Completed(ByteArray(0))
                check(waiter == null) { "concurrent reads are not supported" }
                val w = Waiter(n, CompletableDeferred())
                waiter = w
                Parked(w.deferred)
            }
        val bytes =
            when (slot) {
                is Completed -> slot.bytes
                is Parked ->
                    try {
                        slot.deferred.await()
                    } finally {
                        lock.withLock {
                            if (waiter?.deferred === slot.deferred) waiter = null
                        }
                    }
            }
        if (bytes.isNotEmpty()) onRead?.invoke(bytes.size)
        return bytes
    }

    override suspend fun write(bytes: ByteArray) {
        onWrite?.invoke(bytes)
    }

    override fun close() {
        val done =
            lock.withLock {
                closed = true
                ready()
            }
        deliver(inbox, lock, done) { ready() }
        onClose?.invoke()
    }

    internal fun hasParkedReader(): Boolean = lock.withLock { waiter != null }

    internal suspend fun enqueueThenMarkClosedAndWake(bytes: ByteArray) {
        val done =
            lock.withLock {
                inbox.addLast(bytes.copyOf())
                closed = true
                ready()
            }
        deliver(inbox, lock, done) { ready() }
    }
}
