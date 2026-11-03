package io.bluewallet.echalote

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.net.Socket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A kept-alive HTTPS session that was opened but never used (e.g. by warmUpHttps) and that the
 * server then closed for idleness must not swallow the next request: it has to end fast so
 * httpsFetch reopens, instead of hanging until the caller's abort.
 */
class TlsIdleCloseJvmTest {
    private companion object {
        /** Lets the False Start handshake read the server's Finished, as a warmed session has long done. */
        const val HANDSHAKE_SETTLE_MS = 300L
    }

    /** Like a Tor exit stream after RELAY_END: writes fail once the peer has gone. */
    private class EndedStreamDuplex(
        private val inner: ByteDuplex,
    ) : ByteDuplex {
        @Volatile var ended = false

        override suspend fun read(n: Int): ByteArray = inner.read(n)

        override suspend fun write(bytes: ByteArray) {
            check(!ended) { "stream ended" }
            inner.write(bytes)
        }

        override fun close() = inner.close()
    }

    @BeforeTest
    fun setUp() {
        resetTlsSessionCache()
        setTlsTrustAnchorsForTesting(listOf(tlsFixture("ca.der")))
    }

    @AfterTest
    fun tearDown() {
        httpsSessionFactory = null
        runBlocking { resetHttpsSessions() }
        setTlsTrustAnchorsForTesting(null)
        resetTlsSessionCache()
    }

    private suspend fun open(transport: ByteDuplex): ByteDuplex = wrapTls(transport, "echalote.test", Abort())

    private fun socket(server: TestTlsServer) = SocketDuplex(Socket("127.0.0.1", server.port))

    @Test
    fun unusedSession_seesServerCloseWithoutWriting() {
        TestTlsServer("valid.p12", idleCloseFirst = 1).use { server ->
            runBlocking {
                val tls = open(socket(server))
                try {
                    val eof = withTimeout(5_000) { tls.read(1024) }
                    assertEquals(0, eof.size, "server close must surface as EOF")
                } finally {
                    tls.close()
                }
            }
        }
    }

    @Test
    fun failedTransportWrite_wakesReader() {
        TestTlsServer("valid.p12", idleCloseFirst = 0).use { server ->
            runBlocking {
                val transport = EndedStreamDuplex(socket(server))
                val tls = open(transport)
                try {
                    delay(HANDSHAKE_SETTLE_MS)
                    transport.ended = true
                    val ended =
                        withTimeout(5_000) {
                            runCatching {
                                tls.write("GET / HTTP/1.1\r\nHost: echalote.test\r\n\r\n".encodeToByteArray())
                                tls.read(1024)
                            }
                        }
                    assertTrue(ended.isFailure || ended.getOrThrow().isEmpty(), "expected EOF or an error, got data")
                } finally {
                    tls.close()
                }
            }
        }
    }

    @Test
    fun warmedSessionEndedByServer_httpsFetchReopensPromptly() {
        TestTlsServer("valid.p12", idleCloseFirst = 1).use { server ->
            val transports = ArrayList<EndedStreamDuplex>()
            httpsSessionFactory = { _, _, _ ->
                val transport = EndedStreamDuplex(socket(server)).also { transports += it }
                val tls = open(transport)
                HttpsSession(tls) { tls.close() }
            }
            runBlocking {
                warmUpHttps("https://echalote.test/")
                delay(HANDSHAKE_SETTLE_MS)
                transports.single().ended = true
                val res = withTimeout(10_000) { httpsFetch("https://echalote.test/", Abort()) }
                assertEquals(200, res.status)
                assertEquals(2, transports.size, "the stale warmed session must be replaced")
            }
        }
    }
}
