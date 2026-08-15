package org.hazae41.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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
    val mutex = Mutex()
}

private class Waiter(
    val n: Int,
    val deferred: CompletableDeferred<ByteArray>,
)

fun pairedByteDuplexes(): Pair<ByteDuplex, ByteDuplex> {
    val leftState = DuplexSide()
    val rightState = DuplexSide()

    fun take(state: DuplexSide, n: Int): ByteArray? {
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

    fun wake(state: DuplexSide) {
        val waiter = state.waiter ?: return
        if (state.closed) {
            state.waiter = null
            waiter.deferred.complete(ByteArray(0))
            return
        }
        val chunk = take(state, waiter.n)
        if (chunk != null) {
            state.waiter = null
            waiter.deferred.complete(chunk)
        } else if (state.peerClosed) {
            state.waiter = null
            waiter.deferred.complete(ByteArray(0))
        }
    }

    fun make(state: DuplexSide, peer: DuplexSide): ByteDuplex =
        object : ByteDuplex {
            override suspend fun read(n: Int): ByteArray {
                val deferred: CompletableDeferred<ByteArray>? = state.mutex.withLock {
                    if (state.closed) return ByteArray(0)
                    val chunk = take(state, n)
                    if (chunk != null) return chunk
                    if (state.peerClosed) return ByteArray(0)
                    check(state.waiter == null) { "concurrent reads are not supported" }
                    val waiter = Waiter(n, CompletableDeferred())
                    state.waiter = waiter
                    waiter.deferred
                }
                return deferred?.await() ?: ByteArray(0)
            }

            override suspend fun write(bytes: ByteArray) {
                peer.mutex.withLock {
                    if (state.closed || peer.closed) {
                        throw IllegalStateException("cannot write to closed duplex")
                    }
                    peer.inbox.addLast(bytes.copyOf())
                    wake(peer)
                }
            }

            override fun close() {
                state.closed = true
                wake(state)
                peer.peerClosed = true
                wake(peer)
            }
        }

    return make(leftState, rightState) to make(rightState, leftState)
}

internal suspend fun ByteDuplex.readExact(n: Int): ByteArray {
    if (n == 0) return ByteArray(0)
    val out = ByteArray(n)
    var off = 0
    while (off < n) {
        val chunk = read(n - off)
        if (chunk.isEmpty()) throw IllegalStateException("unexpected EOF")
        chunk.copyInto(out, off)
        off += chunk.size
    }
    return out
}

internal suspend fun pipeDuplex(src: ByteDuplex, dst: ByteDuplex) {
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
    private val mutex = Mutex()
    private val inbox = ArrayDeque<ByteArray>()
    private var closed = false
    private var waiter: Waiter? = null
    var onWrite: (suspend (ByteArray) -> Unit)? = null
    var onClose: (() -> Unit)? = null

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

    private fun wake() {
        val w = waiter ?: return
        if (closed) {
            waiter = null
            w.deferred.complete(ByteArray(0))
            return
        }
        val chunk = take(w.n)
        if (chunk != null) {
            waiter = null
            w.deferred.complete(chunk)
        }
    }

    suspend fun enqueue(bytes: ByteArray) {
        mutex.withLock {
            if (closed) return
            inbox.addLast(bytes.copyOf())
            wake()
        }
    }

    fun error(reason: Throwable) {
        closed = true
        waiter?.deferred?.completeExceptionally(reason)
        waiter = null
        onClose?.invoke()
    }

    override suspend fun read(n: Int): ByteArray {
        val deferred: CompletableDeferred<ByteArray>? = mutex.withLock {
            if (closed && inbox.isEmpty()) return ByteArray(0)
            val chunk = take(n)
            if (chunk != null) return chunk
            if (closed) return ByteArray(0)
            check(waiter == null) { "concurrent reads are not supported" }
            val w = Waiter(n, CompletableDeferred())
            waiter = w
            w.deferred
        }
        return deferred?.await() ?: ByteArray(0)
    }

    override suspend fun write(bytes: ByteArray) {
        onWrite?.invoke(bytes)
    }

    override fun close() {
        closed = true
        wake()
        onClose?.invoke()
    }
}
