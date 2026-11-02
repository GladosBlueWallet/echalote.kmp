package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import platform.posix.EINTR
import platform.posix.IPPROTO_TCP
import platform.posix.SHUT_RDWR
import platform.posix.SOL_SOCKET
import platform.posix.SO_RCVTIMEO
import platform.posix.SO_SNDTIMEO
import platform.posix.TCP_NODELAY
import platform.posix.close
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.shutdown
import platform.posix.timeval

/**
 * A connected POSIX TCP socket as a [ByteDuplex], used for direct relay mode on iOS.
 *
 * Reads and writes block a thread from [Dispatchers.IO], like the JVM `Socket` version. [close]
 * shuts the socket down first, which wakes a blocked `recv` (it returns 0, read as EOF); the fd
 * itself is closed only once no read or write is still using it, so a racing call can never
 * touch a recycled fd number.
 */
@OptIn(ExperimentalForeignApi::class)
private class PosixSocketDuplex(
    private val fd: Int,
) : ByteDuplex {
    private val lock = SpinLock()
    private val writeLock = Mutex()
    private var users = 0
    private var closed = false
    private var released = false

    private fun enter(): Boolean =
        lock.withLock {
            if (closed) {
                false
            } else {
                users++
                true
            }
        }

    private fun exit() {
        val release =
            lock.withLock {
                users--
                takeRelease()
            }
        if (release) platform.posix.close(fd)
    }

    /** Under [lock]: true exactly once, when closed and no call still uses the fd. */
    private fun takeRelease(): Boolean {
        if (!closed || users != 0 || released) return false
        released = true
        return true
    }

    override suspend fun read(n: Int): ByteArray {
        if (n <= 0 || !enter()) return ByteArray(0)
        try {
            return withContext(Dispatchers.IO) { recvSome(n) }
        } finally {
            exit()
        }
    }

    private fun recvSome(n: Int): ByteArray {
        val buf = ByteArray(n)
        val got =
            buf.usePinned { pinned ->
                var r: Long
                do {
                    r = recv(fd, pinned.addressOf(0), n.convert(), 0)
                } while (r < 0 && posixErrno() == EINTR)
                r
            }
        // 0 = orderly EOF; < 0 = reset, shut down by close(), or another error: all end the stream.
        return if (got <= 0) ByteArray(0) else buf.copyOf(got.toInt())
    }

    override suspend fun write(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        writeLock.withLock {
            check(enter()) { "socket closed" }
            try {
                withContext(Dispatchers.IO) { sendAll(bytes) }
            } finally {
                exit()
            }
        }
    }

    private fun sendAll(bytes: ByteArray) {
        bytes.usePinned { pinned ->
            var off = 0
            while (off < bytes.size) {
                // SO_NOSIGPIPE is set at connect, so a dead peer is an error here, not a signal.
                val n = send(fd, pinned.addressOf(off), (bytes.size - off).convert(), 0)
                if (n < 0 && posixErrno() == EINTR) continue
                check(n > 0) { "send failed (errno ${posixErrno()})" }
                off += n.toInt()
            }
        }
    }

    override fun close() {
        val release =
            lock.withLock {
                if (closed) {
                    false
                } else {
                    closed = true
                    shutdown(fd, SHUT_RDWR)
                    takeRelease()
                }
            }
        if (release) platform.posix.close(fd)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun configureLongLived(fd: Int) =
    memScoped {
        // posixConnect leaves HTTP-style per-call timeouts on the socket; a Tor link stays idle
        // for minutes between requests, so reads must block until data, EOF, or close().
        val tv = alloc<timeval>()
        tv.tv_sec = 0.convert()
        tv.tv_usec = 0.convert()
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.ptr, sizeOf<timeval>().convert())
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv.ptr, sizeOf<timeval>().convert())
        val one = alloc<IntVar>()
        one.value = 1
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, one.ptr, sizeOf<IntVar>().convert())
    }

/**
 * Direct relay mode on iOS: a blocking POSIX socket (resolve, non-blocking connect with
 * [timeoutMs], then blocking I/O), sharing the connect code with the cleartext HTTP engine.
 * Cancelling the caller shuts the half-open socket down so the connecting thread is freed,
 * and a socket that still finishes connecting after that is closed rather than leaked.
 */
@OptIn(ExperimentalForeignApi::class, ExperimentalCoroutinesApi::class)
@Suppress("TooGenericExceptionCaught") // the fd must be closed on any failure, then rethrown
internal actual suspend fun platformTcpConnect(
    host: String,
    port: Int,
    timeoutMs: Long,
): ByteDuplex? {
    val hook = CancelHook()
    val work =
        CoroutineScope(Dispatchers.IO).async {
            // posixConnect leaves the hook registered on the connected fd (shutdown on cancel).
            val fd = hook.posixConnect(host, port, timeoutMs)
            try {
                configureLongLived(fd)
            } catch (e: Throwable) {
                hook.release { close(fd) }
                throw e
            }
            fd
        }
    val fd =
        try {
            work.await()
        } catch (e: CancellationException) {
            hook.cancel()
            work.invokeOnCompletion { cause ->
                if (cause == null) close(work.getCompleted())
            }
            throw e
        }
    hook.release()
    return PosixSocketDuplex(fd)
}
