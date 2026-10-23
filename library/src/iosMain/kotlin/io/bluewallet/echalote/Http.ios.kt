package io.bluewallet.echalote

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSData
import platform.Foundation.NSHTTPURLResponse
import platform.Foundation.NSMutableURLRequest
import platform.Foundation.NSURL
import platform.Foundation.NSURLSession
import platform.Foundation.NSURLSessionConfiguration
import platform.Foundation.create
import platform.Foundation.dataTaskWithRequest
import platform.Foundation.setHTTPBody
import platform.Foundation.setHTTPMethod
import platform.Foundation.setValue
import platform.posix.AF_UNSPEC
import platform.posix.EAGAIN
import platform.posix.EINPROGRESS
import platform.posix.EINTR
import platform.posix.ETIMEDOUT
import platform.posix.EWOULDBLOCK
import platform.posix.F_GETFL
import platform.posix.F_SETFL
import platform.posix.IPPROTO_TCP
import platform.posix.O_NONBLOCK
import platform.posix.POLLERR
import platform.posix.POLLHUP
import platform.posix.POLLNVAL
import platform.posix.POLLOUT
import platform.posix.SHUT_RDWR
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_ERROR
import platform.posix.SO_NOSIGPIPE
import platform.posix.SO_RCVTIMEO
import platform.posix.SO_SNDTIMEO
import platform.posix.addrinfo
import platform.posix.close
import platform.posix.connect
import platform.posix.errno
import platform.posix.fcntl
import platform.posix.freeaddrinfo
import platform.posix.getaddrinfo
import platform.posix.getsockopt
import platform.posix.memset
import platform.posix.poll
import platform.posix.pollfd
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.shutdown
import platform.posix.socket
import platform.posix.socklen_tVar
import platform.posix.timeval
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@OptIn(ExperimentalForeignApi::class)
private fun NSData.toByteArray(): ByteArray {
    val size = length.toInt()
    if (size == 0) return ByteArray(0)
    val out = ByteArray(size)
    out.usePinned { pinned ->
        platform.posix.memcpy(pinned.addressOf(0), bytes, size.convert())
    }
    return out
}

actual fun defaultHttpEngine(): HttpEngine {
    val session = NSURLSession.sessionWithConfiguration(NSURLSessionConfiguration.ephemeralSessionConfiguration)
    return HttpEngine { method, url, headers, body, timeoutMs, decompress ->
        val onDownload = http1ProgressSink()
        if (usesCleartextHttp1(url)) {
            cancellableBlocking(Dispatchers.Default) { hook ->
                hook.http1OverTcp(method, url, headers, body, timeoutMs, onDownload)
            }
        } else {
            httpsUrlSession(session, method, url, headers, body, timeoutMs, decompress)
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun CancelHook.http1OverTcp(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
    onDownload: ((Int, Int?) -> Unit)?,
): HttpResponse {
    val parsed = parseHttpUrl(url)
    val timing = Http1Timing(url)
    // posixConnect leaves the cancel hook registered on the connected fd (shutdown on cancel).
    val fd = posixConnect(parsed.host, parsed.port, timeoutMs)
    timing.connected()
    try {
        sendAll(fd, buildHttp1Request(method, parsed, headers, body))
        return parseHttp1Response(recvHttp1(fd, onDownload, timing)).also { timing.done(it) }
    } finally {
        release { close(fd) }
    }
}

/**
 * Resolves and connects, trying each address in turn. Each socket gets the cancel hook
 * (shutdown) as soon as it exists, and the connect wait polls in short slices that check
 * [CancelHook.isCancelled], so a cancelled request frees this thread promptly. On success the
 * hook stays registered on the returned fd; the caller releases it.
 */
@OptIn(ExperimentalForeignApi::class)
private fun CancelHook.posixConnect(
    host: String,
    port: Int,
    timeoutMs: Long,
): Int =
    memScoped {
        throwIfCancelled()
        val hints = alloc<addrinfo>()
        memset(hints.ptr, 0, kotlinx.cinterop.sizeOf<addrinfo>().convert())
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        val result = alloc<CPointerVar<addrinfo>>()
        val err = getaddrinfo(host, port.toString(), hints.ptr, result.ptr)
        check(err == 0) { "getaddrinfo failed for $host:$port ($err)" }
        val head = result.value
        try {
            var ai: CPointer<addrinfo>? = head
            while (ai != null) {
                throwIfCancelled()
                val info = ai.pointed
                val fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
                if (fd >= 0) {
                    register { shutdown(fd, SHUT_RDWR) }
                    val connected =
                        try {
                            disableSigPipe(fd)
                            connectWithTimeout(fd, info, timeoutMs)
                        } catch (e: Throwable) {
                            release { close(fd) }
                            throw e
                        }
                    if (connected) {
                        applySocketTimeouts(fd, timeoutMs)
                        return@memScoped fd
                    }
                    release { close(fd) }
                }
                ai = info.ai_next
            }
            throwIfCancelled()
            error("connect failed for $host:$port")
        } finally {
            freeaddrinfo(head)
        }
    }

private fun CancelHook.throwIfCancelled() {
    check(!isCancelled) { "http request cancelled" }
}

@OptIn(ExperimentalForeignApi::class)
private fun disableSigPipe(fd: Int) =
    memScoped {
        val one = alloc<IntVar>()
        one.value = 1
        check(
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, one.ptr, kotlinx.cinterop.sizeOf<IntVar>().convert()) == 0,
        ) { "SO_NOSIGPIPE failed" }
    }

@OptIn(ExperimentalForeignApi::class)
private fun CancelHook.connectWithTimeout(
    fd: Int,
    info: addrinfo,
    timeoutMs: Long,
): Boolean {
    setNonBlocking(fd, true)
    val rc = connect(fd, info.ai_addr, info.ai_addrlen)
    val connected = rc == 0 || (posixErrno() == EINPROGRESS && pollConnected(fd, timeoutMs) && socketError(fd) == 0)
    throwIfCancelled()
    setNonBlocking(fd, false)
    return connected
}

@OptIn(ExperimentalForeignApi::class)
private fun setNonBlocking(
    fd: Int,
    enabled: Boolean,
) {
    val flags = fcntl(fd, F_GETFL, 0)
    check(flags != -1) { "fcntl F_GETFL failed" }
    val next = if (enabled) flags or O_NONBLOCK else flags and O_NONBLOCK.inv()
    check(fcntl(fd, F_SETFL, next) != -1) { "fcntl F_SETFL failed" }
}

/** Longest single poll while waiting for connect, so cancellation is noticed quickly. */
private const val CONNECT_POLL_SLICE_MS = 100L

/**
 * Waits up to [timeoutMs] in total for the non-blocking connect on [fd], polling in
 * [CONNECT_POLL_SLICE_MS] slices and giving up as soon as the hook is cancelled.
 */
@OptIn(ExperimentalForeignApi::class)
private fun CancelHook.pollConnected(
    fd: Int,
    timeoutMs: Long,
): Boolean {
    val started =
        kotlin.time.TimeSource.Monotonic
            .markNow()
    val total = timeoutMs.coerceAtLeast(1L)
    var connected = false
    var waiting = true
    memScoped {
        val pfd = alloc<pollfd>()
        pfd.fd = fd
        pfd.events = POLLOUT.toShort()
        while (waiting && !isCancelled) {
            val remaining = total - started.elapsedNow().inWholeMilliseconds
            pfd.revents = 0
            val n = if (remaining > 0L) poll(pfd.ptr, 1.convert(), minOf(remaining, CONNECT_POLL_SLICE_MS).toInt()) else -1
            // n == 0 (slice elapsed) or EINTR: keep waiting; any other error or timeout: give up.
            if (n > 0) {
                val revents = pfd.revents.toInt()
                connected = revents and (POLLERR or POLLHUP or POLLNVAL) == 0 && revents and POLLOUT != 0
                waiting = false
            } else if (n < 0 && (remaining <= 0L || posixErrno() != EINTR)) {
                waiting = false
            }
        }
    }
    return connected
}

@OptIn(ExperimentalForeignApi::class)
private fun socketError(fd: Int): Int =
    memScoped {
        val err = alloc<IntVar>()
        val len = alloc<socklen_tVar>()
        len.value = kotlinx.cinterop.sizeOf<IntVar>().convert()
        val rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, err.ptr, len.ptr)
        if (rc != 0) posixErrno() else err.value
    }

private fun posixErrno(): Int = errno

@OptIn(ExperimentalForeignApi::class)
private fun applySocketTimeouts(
    fd: Int,
    timeoutMs: Long,
) {
    val ms = timeoutMs.coerceAtLeast(1L)
    memScoped {
        val tv = alloc<timeval>()
        tv.tv_sec = (ms / 1000L).convert()
        tv.tv_usec = ((ms % 1000L) * 1000L).convert()
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.ptr, kotlinx.cinterop.sizeOf<timeval>().convert())
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv.ptr, kotlinx.cinterop.sizeOf<timeval>().convert())
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun sendAll(
    fd: Int,
    data: ByteArray,
) {
    data.usePinned { pinned ->
        var off = 0
        while (off < data.size) {
            val n = send(fd, pinned.addressOf(off), (data.size - off).convert(), 0)
            check(n > 0) { "send failed" }
            off += n.toInt()
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun recvHttp1(
    fd: Int,
    onDownload: ((Int, Int?) -> Unit)?,
    timing: Http1Timing,
): ByteArray {
    val buf = ByteArray(16 * 1024)
    return readHttp1Raw(onDownload = onDownload) { recvOnce(fd, buf).also { timing.firstByte() } }
}

@OptIn(ExperimentalForeignApi::class)
private fun recvOnce(
    fd: Int,
    buf: ByteArray,
): ByteArray? {
    buf.usePinned { pinned ->
        while (true) {
            val n = recv(fd, pinned.addressOf(0), buf.size.convert(), 0)
            when {
                n > 0 -> return buf.copyOf(n.toInt())
                n.toLong() == 0L -> return null
                else -> {
                    val e = posixErrno()
                    if (e == EINTR) continue
                    check(e != EAGAIN && e != EWOULDBLOCK && e != ETIMEDOUT) { "HTTP socket timeout" }
                    error("recv failed ($e)")
                }
            }
        }
    }
    error("unreachable")
}

@OptIn(ExperimentalForeignApi::class)
private suspend fun httpsUrlSession(
    session: NSURLSession,
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
    @Suppress("UNUSED_PARAMETER") decompress: Boolean,
): HttpResponse =
    suspendCancellableCoroutine { cont ->
        val nsUrl =
            NSURL.URLWithString(url) ?: run {
                cont.resumeWithException(IllegalArgumentException("bad url $url"))
                return@suspendCancellableCoroutine
            }
        val req = NSMutableURLRequest.requestWithURL(nsUrl)
        req.setHTTPMethod(method)
        req.setTimeoutInterval(timeoutMs / 1000.0)
        if (!decompress) req.setValue("identity", forHTTPHeaderField = "Accept-Encoding")
        for ((k, v) in headers) req.setValue(v, forHTTPHeaderField = k)
        if (body.isNotEmpty()) {
            body.usePinned { pinned ->
                req.setHTTPBody(NSData.create(bytes = pinned.addressOf(0), length = body.size.convert()))
            }
        }
        val task =
            session.dataTaskWithRequest(req) { data, response, error ->
                if (!cont.isActive) return@dataTaskWithRequest
                if (error != null) {
                    cont.resumeWithException(Exception(error.localizedDescription))
                    return@dataTaskWithRequest
                }
                val http = response as? NSHTTPURLResponse
                val status = http?.statusCode?.toInt() ?: 0
                val bytes = data?.toByteArray() ?: ByteArray(0)
                if (bytes.size > MAX_HTTP1_BODY) {
                    cont.resumeWithException(IllegalArgumentException("HTTP body too large"))
                    return@dataTaskWithRequest
                }
                val hdrs = mutableMapOf<String, String>()
                val dict = http?.allHeaderFields
                if (dict != null) {
                    for ((k, v) in dict) {
                        hdrs[k.toString()] = v.toString()
                    }
                }
                cont.resume(HttpResponse(status, bytes, hdrs))
            }
        cont.invokeOnCancellation { task.cancel() }
        task.resume()
    }
