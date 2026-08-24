package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.posix.AF_INET
import platform.posix.IPPROTO_TCP
import platform.posix.SOCK_STREAM
import platform.posix.close
import platform.posix.connect
import platform.posix.htonl
import platform.posix.htons
import platform.posix.memset
import platform.posix.recv
import platform.posix.send
import platform.posix.sockaddr_in
import platform.posix.socket

/**
 * Bonus linux target: HTTP/1.1 over TCP (clearnet directory). HTTPS meek is not
 * implemented on linuxX64; inject [HttpEngine] for tests or use JVM/Android/iOS.
 */
@OptIn(ExperimentalForeignApi::class)
actual fun defaultHttpEngine(): HttpEngine = HttpEngine { method, url, headers, body, timeoutMs, _ ->
    if (url.startsWith("https://")) {
        throw UnsupportedOperationException("linuxX64 default HttpEngine is HTTP-only; inject an engine for HTTPS meek")
    }
    val parsed = parseHttpUrl(url)
    memScoped {
        val fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        check(fd >= 0) { "socket failed" }
        try {
            val addr = alloc<sockaddr_in>()
            memset(addr.ptr, 0, kotlinx.cinterop.sizeOf<sockaddr_in>().convert())
            addr.sin_family = AF_INET.convert()
            addr.sin_port = htons(parsed.port.toUShort())
            addr.sin_addr.s_addr = ipv4ToNetworkOrder(parsed.host)
            val rc = connect(fd, addr.ptr.reinterpret(), kotlinx.cinterop.sizeOf<sockaddr_in>().convert())
            check(rc == 0) { "connect failed" }

            sendAll(fd, buildHttp1Request(method, parsed, headers, body))

            val raw = recvAll(fd)
            return@memScoped parseHttp1Response(raw)
        } finally {
            close(fd)
        }
    }
}

private fun ipv4ToNetworkOrder(host: String): UInt {
    val parts = host.split('.')
    require(parts.size == 4) { "linux HTTP engine requires dotted IPv4, got $host" }
    val bytes = parts.map { it.toUInt() }
    require(bytes.all { it <= 255u }) { "invalid IPv4 $host" }
    val hostOrder = (bytes[0] shl 24) or (bytes[1] shl 16) or (bytes[2] shl 8) or bytes[3]
    return htonl(hostOrder)
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
private fun recvAll(fd: Int): ByteArray {
    val chunks = ArrayList<ByteArray>()
    val buf = ByteArray(16 * 1024)
    buf.usePinned { pinned ->
        while (true) {
            val n = recv(fd, pinned.addressOf(0), buf.size.convert(), 0)
            if (n <= 0) break
            chunks += buf.copyOf(n.toInt())
        }
    }
    return concatBytes(*chunks.toTypedArray())
}
