package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

internal fun tlsFixture(name: String): ByteArray =
    requireNotNull(TestTlsServer::class.java.getResourceAsStream("/tls/$name")) { "missing fixture $name" }
        .use { it.readBytes() }

/** Plain JSSE TLS 1.2 server on 127.0.0.1 serving one fixed HTTP response per connection. */
internal class TestTlsServer(
    p12: String,
) : Closeable {
    private val server: SSLServerSocket
    val errors = LinkedBlockingQueue<Throwable>()
    val port: Int get() = server.localPort

    init {
        val pass = "changeit".toCharArray()
        val ks = KeyStore.getInstance("PKCS12").apply { load(tlsFixture(p12).inputStream(), pass) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, pass) }
        val ctx = SSLContext.getInstance("TLSv1.2").apply { init(kmf.keyManagers, null, null) }
        server = ctx.serverSocketFactory.createServerSocket(0, 16, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        server.enabledProtocols = arrayOf("TLSv1.2")
        server.enabledCipherSuites = arrayOf("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        thread(isDaemon = true, name = "test-tls-server") {
            while (!server.isClosed) {
                val sock = runCatching { server.accept() as SSLSocket }.getOrNull() ?: break
                thread(isDaemon = true) { serve(sock) }
            }
        }
    }

    private fun serve(sock: SSLSocket) {
        try {
            sock.soTimeout = 15_000
            sock.startHandshake()
            val input = sock.inputStream
            val seen = StringBuilder()
            while (!seen.endsWith("\r\n\r\n")) {
                val b = input.read()
                if (b < 0) return
                seen.append(b.toChar())
            }
            sock.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".encodeToByteArray())
            sock.outputStream.flush()
        } catch (e: Throwable) {
            errors.add(e)
        } finally {
            runCatching { sock.close() }
        }
    }

    fun awaitError(timeoutMs: Long = 5_000): Throwable? = errors.poll(timeoutMs, TimeUnit.MILLISECONDS)

    override fun close() {
        runCatching { server.close() }
    }
}

/** Blocking java.net.Socket as an echalote [ByteDuplex]. */
internal class SocketDuplex(
    private val socket: Socket,
) : ByteDuplex {
    override suspend fun read(n: Int): ByteArray =
        withContext(Dispatchers.IO) {
            val buf = ByteArray(n)
            val r = runCatching { socket.getInputStream().read(buf) }.getOrDefault(-1)
            if (r <= 0) ByteArray(0) else buf.copyOf(r)
        }

    override suspend fun write(bytes: ByteArray) =
        withContext(Dispatchers.IO) {
            socket.getOutputStream().write(bytes)
            socket.getOutputStream().flush()
        }

    override fun close() {
        runCatching { socket.close() }
    }
}

internal suspend fun httpGetOver(
    tls: ByteDuplex,
    host: String,
    path: String = "/",
): String {
    tls.write("GET $path HTTP/1.1\r\nHost: $host\r\nUser-Agent: echalote-test\r\nConnection: close\r\n\r\n".encodeToByteArray())
    val out = StringBuilder()
    var open = true

    fun headersRead() = out.startsWith("HTTP/") && out.contains("\r\n\r\n")
    while (open && out.length < 64 * 1024 && !headersRead()) {
        val chunk = runCatching { tls.read(16 * 1024) }.getOrDefault(ByteArray(0))
        open = chunk.isNotEmpty()
        out.append(chunk.decodeToString())
    }
    return out.toString()
}
