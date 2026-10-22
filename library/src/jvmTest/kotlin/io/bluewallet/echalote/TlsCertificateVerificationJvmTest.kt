package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import java.net.Socket
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsCertificateVerificationJvmTest {
    private val caDer = tlsFixture("ca.der")

    @BeforeTest
    fun setUp() {
        resetTlsSessionCache()
        setTlsTrustAnchorsForTesting(listOf(caDer))
    }

    @AfterTest
    fun tearDown() {
        setTlsTrustAnchorsForTesting(null)
        resetTlsSessionCache()
    }

    private fun connect(
        server: TestTlsServer,
        host: String,
        trust: TlsTrust = TlsTrust.WebPki,
    ): ByteDuplex =
        runBlocking {
            val transport = SocketDuplex(Socket("127.0.0.1", server.port))
            try {
                wrapTlsWithTrust(transport, host, Abort(), trust)
            } catch (e: Throwable) {
                transport.close()
                throw e
            }
        }

    @Test
    fun validLeaf_withInjectedAnchor_isAccepted() {
        TestTlsServer("valid.p12").use { server ->
            val tls = connect(server, "echalote.test")
            try {
                val res = runBlocking { httpGetOver(tls, "echalote.test") }
                assertTrue(res.startsWith("HTTP/1.1 200"), res)
            } finally {
                tls.close()
            }
            assertNotNull(lookupTlsSession("echalote.test"), "a verified session may be cached")
        }
    }

    @Test
    fun validLeaf_wildcardSan_isAccepted() {
        TestTlsServer("valid.p12").use { server ->
            connect(server, "api.wild.echalote.test").close()
        }
    }

    @Test
    fun validLeaf_withoutInjectedAnchor_isRejected() {
        setTlsTrustAnchorsForTesting(null)
        TestTlsServer("valid.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "echalote.test") }
        }
    }

    @Test
    fun selfSigned_isRejected() {
        TestTlsServer("selfsigned.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "echalote.test") }
        }
    }

    @Test
    fun wrongHost_isRejected_withBadCertificateAlert() {
        TestTlsServer("wronghost.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "echalote.test") }
            val err = server.awaitError()
            assertNotNull(err, "server should see the handshake abort")
            assertTrue(err.toString().contains("bad_certificate"), "expected alert 42, server saw: $err")
        }
    }

    @Test
    fun requestedHostNotInSan_isRejected() {
        TestTlsServer("valid.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "evil.test") }
            assertFailsWith<TlsCertificateError> { connect(server, "wild.echalote.test") }
        }
    }

    @Test
    fun expired_isRejected() {
        TestTlsServer("expired.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "echalote.test") }
        }
    }

    @Test
    fun failedVerification_isNeverCached_andDropsOldSession() {
        rememberTlsSession(
            TlsResumption(
                host = "echalote.test",
                master = ByteArray(48) { 9 },
                sessionId = ByteArray(0),
                ticket = "stale-ticket".encodeToByteArray(),
                ems = true,
                expiresAtMs = Long.MAX_VALUE,
            ),
        )
        TestTlsServer("wronghost.p12").use { server ->
            assertFailsWith<TlsCertificateError> { connect(server, "echalote.test") }
        }
        assertNull(lookupTlsSession("echalote.test"))
    }

    @Test
    fun verifiedSession_resumesOnSecondConnection() {
        TestTlsServer("valid.p12").use { server ->
            connect(server, "echalote.test").close()
            assertNotNull(lookupTlsSession("echalote.test"))
            val tls = connect(server, "echalote.test")
            try {
                val res = runBlocking { httpGetOver(tls, "echalote.test") }
                assertTrue(res.startsWith("HTTP/1.1 200"), res)
            } finally {
                tls.close()
            }
        }
    }

    private fun connectPublic(
        server: TestTlsServer,
        host: String,
        viaEchaloteObject: Boolean,
    ): ByteDuplex =
        runBlocking {
            val transport = SocketDuplex(Socket("127.0.0.1", server.port))
            try {
                if (viaEchaloteObject) Echalote.wrapTls(transport, host) else wrapTls(transport, host)
            } catch (e: Throwable) {
                transport.close()
                throw e
            }
        }

    @Test
    fun publicWrapTls_alwaysVerifies() {
        setTlsTrustAnchorsForTesting(null)
        for (viaObject in listOf(false, true)) {
            for (fixture in listOf("selfsigned.p12", "valid.p12", "wronghost.p12", "expired.p12")) {
                TestTlsServer(fixture).use { server ->
                    assertFailsWith<TlsCertificateError>("$fixture viaObject=$viaObject") {
                        connectPublic(server, "echalote.test", viaObject)
                    }
                }
            }
        }
        assertNull(lookupTlsSession("echalote.test"))
    }

    @Test
    fun publicWrapTls_acceptsTrustedChain() {
        for (viaObject in listOf(false, true)) {
            TestTlsServer("valid.p12").use { server ->
                connectPublic(server, "echalote.test", viaObject).close()
            }
            resetTlsSessionCache()
        }
    }

    @Test
    fun torLink_stillAcceptsSelfSigned_andIsNeverCached() {
        setTlsTrustAnchorsForTesting(null)
        TestTlsServer("selfsigned.p12").use { server ->
            val tls = connect(server, "echalote.test", TlsTrust.TorLink)
            try {
                val res = runBlocking { httpGetOver(tls, "echalote.test") }
                assertTrue(res.startsWith("HTTP/1.1 200"), res)
            } finally {
                tls.close()
            }
        }
        assertNull(lookupTlsSession("echalote.test"), "TorLink sessions must not be cached")
    }

    @Test
    fun torLinkDuplex_exposesLeafCertificate() {
        TestTlsServer("selfsigned.p12").use { server ->
            runBlocking {
                val transport = SocketDuplex(Socket("127.0.0.1", server.port))
                val tls = TlsClientDuplex(null, transport, TlsTrust.TorLink)
                try {
                    val leaf = tls.leafCertDer.await()
                    assertTrue(leaf.contentEquals(tlsFixture("selfsigned.der")))
                } finally {
                    tls.close()
                    transport.close()
                }
            }
        }
    }

    @Test
    fun webPkiChain_acceptsAnchoredChain_rejectsHostMismatchAndExpiry() {
        runBlocking {
            val chain = listOf(tlsFixture("valid.der"), caDer)
            verifyWebPkiChain(chain, "echalote.test")
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(chain, "other.test") }
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(listOf(tlsFixture("expired.der"), caDer), "echalote.test") }
        }
    }
}
