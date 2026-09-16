package io.bluewallet.echalote

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
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
import kotlinx.coroutines.withContext
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
import platform.posix.IPPROTO_TCP
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_RCVTIMEO
import platform.posix.SO_SNDTIMEO
import platform.posix.addrinfo
import platform.posix.close
import platform.posix.connect
import platform.posix.freeaddrinfo
import platform.posix.getaddrinfo
import platform.posix.memset
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.socket
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
        if (usesCleartextHttp1(url)) {
            withContext(Dispatchers.Default) {
                http1OverTcp(method, url, headers, body, timeoutMs)
            }
        } else {
            httpsUrlSession(session, method, url, headers, body, timeoutMs, decompress)
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun http1OverTcp(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
): HttpResponse {
    val parsed = parseHttpUrl(url)
    val fd = posixConnect(parsed.host, parsed.port, timeoutMs)
    try {
        sendAll(fd, buildHttp1Request(method, parsed, headers, body))
        return parseHttp1Response(recvHttp1(fd))
    } finally {
        close(fd)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun posixConnect(host: String, port: Int, timeoutMs: Long): Int = memScoped {
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
            val info = ai.pointed
            val fd = socket(info.ai_family, info.ai_socktype, info.ai_protocol)
            if (fd >= 0) {
                applySocketTimeouts(fd, timeoutMs)
                val rc = connect(fd, info.ai_addr, info.ai_addrlen)
                if (rc == 0) return@memScoped fd
                close(fd)
            }
            ai = info.ai_next
        }
        error("connect failed for $host:$port")
    } finally {
        freeaddrinfo(head)
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun applySocketTimeouts(fd: Int, timeoutMs: Long) {
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
private fun sendAll(fd: Int, data: ByteArray) {
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
private fun recvHttp1(fd: Int): ByteArray {
    val buf = ByteArray(16 * 1024)
    return readHttp1Raw {
        buf.usePinned { pinned ->
            val n = recv(fd, pinned.addressOf(0), buf.size.convert(), 0)
            if (n <= 0) null else buf.copyOf(n.toInt())
        }
    }
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
): HttpResponse = suspendCancellableCoroutine { cont ->
    val nsUrl = NSURL.URLWithString(url) ?: run {
        cont.resumeWithException(IllegalArgumentException("bad url $url"))
        return@suspendCancellableCoroutine
    }
    val req = NSMutableURLRequest.requestWithURL(nsUrl)
    req.setHTTPMethod(method)
    req.setTimeoutInterval(timeoutMs / 1000.0)
    for ((k, v) in headers) req.setValue(v, forHTTPHeaderField = k)
    if (body.isNotEmpty()) {
        body.usePinned { pinned ->
            req.setHTTPBody(NSData.create(bytes = pinned.addressOf(0), length = body.size.convert()))
        }
    }
    val task = session.dataTaskWithRequest(req) { data, response, error ->
        if (error != null) {
            cont.resumeWithException(Exception(error.localizedDescription))
            return@dataTaskWithRequest
        }
        val http = response as? NSHTTPURLResponse
        val status = http?.statusCode?.toInt() ?: 0
        val bytes = data?.toByteArray() ?: ByteArray(0)
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
