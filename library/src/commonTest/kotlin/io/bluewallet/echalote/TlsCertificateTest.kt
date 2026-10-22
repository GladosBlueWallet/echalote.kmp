package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsCertificateTest {
    // --- RFC 6125 name matching -------------------------------------------------

    @Test
    fun dnsName_exactMatch_isCaseInsensitive_andIgnoresTrailingDot() {
        assertTrue(hostMatchesDnsName("api.rocketx.exchange", "api.rocketx.exchange"))
        assertTrue(hostMatchesDnsName("API.RocketX.Exchange", "api.rocketx.exchange"))
        assertTrue(hostMatchesDnsName("api.rocketx.exchange.", "api.rocketx.exchange"))
        assertTrue(hostMatchesDnsName("api.rocketx.exchange", "API.ROCKETX.EXCHANGE."))
        assertFalse(hostMatchesDnsName("api.rocketx.exchange", "rocketx.exchange"))
        assertFalse(hostMatchesDnsName("rocketx.exchange", "api.rocketx.exchange"))
        assertFalse(hostMatchesDnsName("evilrocketx.exchange", "rocketx.exchange"))
    }

    @Test
    fun dnsName_wildcard_coversExactlyOneLeftmostLabel() {
        assertTrue(hostMatchesDnsName("api.rocketx.exchange", "*.rocketx.exchange"))
        assertFalse(hostMatchesDnsName("rocketx.exchange", "*.rocketx.exchange"))
        assertFalse(hostMatchesDnsName("a.b.rocketx.exchange", "*.rocketx.exchange"))
        assertFalse(hostMatchesDnsName(".rocketx.exchange", "*.rocketx.exchange"))
    }

    @Test
    fun dnsName_rejectsUnsafeWildcards() {
        assertFalse(hostMatchesDnsName("example.com", "*.com"), "wildcard over a single-label suffix")
        assertFalse(hostMatchesDnsName("anything", "*"))
        assertFalse(hostMatchesDnsName("foo.example.com", "f*.example.com"), "partial-label wildcard")
        assertFalse(hostMatchesDnsName("foo.example.com", "*o.example.com"))
        assertFalse(hostMatchesDnsName("a.foo.example.com", "a.*.example.com"), "non-leftmost wildcard")
        assertFalse(hostMatchesDnsName("x.y.example.com", "*.*.example.com"))
        assertFalse(hostMatchesDnsName("127.0.0.1", "*.0.0.1"), "wildcard must never match an IP")
        assertFalse(hostMatchesDnsName("", ""))
        assertFalse(hostMatchesDnsName("xn--bcher-kva.example", "*n--bcher-kva.example"))
    }

    @Test
    fun ipHost_matchesOnlyIpAddressSans() {
        val sans = SubjectAltNames(dnsNames = listOf("127.0.0.1"), ipAddresses = emptyList())
        assertFalse(sans.matches("127.0.0.1"), "an IP literal must not match a dNSName")
        val ipSans = SubjectAltNames(dnsNames = emptyList(), ipAddresses = listOf(byteArrayOf(127, 0, 0, 1)))
        assertTrue(ipSans.matches("127.0.0.1"))
        assertFalse(ipSans.matches("127.0.0.2"))
        assertFalse(ipSans.matches("localhost"))
    }

    @Test
    fun ipv6Host_matchesSixteenByteIpAddressSans() {
        val addr =
            ByteArray(16).also {
                it[0] = 0x20
                it[1] = 0x01
                it[2] = 0x0d
                it[3] = 0xb8.toByte()
                it[15] = 1
            }
        val sans = SubjectAltNames(dnsNames = listOf("2001:db8::1"), ipAddresses = listOf(addr))
        assertTrue(sans.matches("2001:db8::1"))
        assertTrue(sans.matches("[2001:db8::1]"))
        assertTrue(sans.matches("2001:DB8:0:0:0:0:0:1"))
        assertTrue(sans.matches("2001:db8:0::0:1"))
        assertFalse(sans.matches("2001:db8::2"))
        assertFalse(SubjectAltNames(listOf("2001:db8::1"), emptyList()).matches("2001:db8::1"), "never via dNSName")
        val mapped =
            ByteArray(16).also {
                it[10] = -1
                it[11] = -1
                it[12] = 127
                it[15] = 1
            }
        assertTrue(SubjectAltNames(emptyList(), listOf(mapped)).matches("::ffff:127.0.0.1"))
        val loopback = ByteArray(16).also { it[15] = 1 }
        assertTrue(SubjectAltNames(emptyList(), listOf(loopback)).matches("::1"))
    }

    @Test
    fun parseIpLiteral_rejectsMalformedIpv6() {
        for (bad in listOf("1::2::3", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "12345::", "g::1", ":1", "1:", "fe80::1%eth0", "[::1", "::1.2.3")) {
            assertNull(parseIpLiteral(bad), bad)
        }
        assertEquals(16, parseIpLiteral("1:2:3:4:5:6:7:8")?.size)
        assertEquals(16, parseIpLiteral("::")?.size)
    }

    @Test
    fun nonCanonicalNumericHosts_matchNothing() {
        val ipSans = SubjectAltNames(dnsNames = listOf("10.0.0.1", "1.2.3"), ipAddresses = listOf(byteArrayOf(10, 0, 0, 1)))
        assertTrue(ipSans.matches("10.0.0.1"))
        assertFalse(ipSans.matches("010.0.0.1"), "leading zeros may be read as octal by a resolver")
        assertFalse(ipSans.matches("10.00.0.1"))
        assertFalse(ipSans.matches("1.2.3"), "short-form IPv4 is never a DNS name")
        assertFalse(ipSans.matches("0x0a.0.0.1"))
        assertFalse(SubjectAltNames(listOf("*.0.0.1"), emptyList()).matches("010.0.0.1"))
    }

    // --- SAN extraction from real DER --------------------------------------------

    @Test
    fun subjectAltNames_parsesDnsAndIpEntries() {
        val sans = subjectAltNames(TlsTestCerts.VALID_LEAF)
        assertEquals(listOf("echalote.test", "*.wild.echalote.test"), sans.dnsNames)
        assertEquals(1, sans.ipAddresses.size)
        assertContentEquals(byteArrayOf(127, 0, 0, 1), sans.ipAddresses[0])
    }

    @Test
    fun certificateMatchesHost_usesSans() {
        val leaf = TlsTestCerts.VALID_LEAF
        assertTrue(certificateMatchesHost(leaf, "echalote.test"))
        assertTrue(certificateMatchesHost(leaf, "a.wild.echalote.test"))
        assertTrue(certificateMatchesHost(leaf, "127.0.0.1"))
        assertFalse(certificateMatchesHost(leaf, "valid"), "the subject CN must not be used")
        assertFalse(certificateMatchesHost(leaf, "wild.echalote.test"))
        assertFalse(certificateMatchesHost(leaf, "other.test"))
    }

    @Test
    fun certificateMatchesHost_realRocketxLeaf() {
        val leaf = TlsTestCerts.ROCKETX_LEAF
        assertEquals(listOf("rocketx.exchange", "*.rocketx.exchange"), subjectAltNames(leaf).dnsNames)
        assertTrue(certificateMatchesHost(leaf, "api.rocketx.exchange"))
        assertTrue(certificateMatchesHost(leaf, "rocketx.exchange"))
        assertFalse(certificateMatchesHost(leaf, "api.rocketx.exchange.evil.com"))
    }

    @Test
    fun certificateWithoutSan_matchesNothing() {
        assertTrue(subjectAltNames(TlsTestCerts.TEST_CA).dnsNames.isEmpty())
        assertFalse(certificateMatchesHost(TlsTestCerts.TEST_CA, "Echalote Test Root CA"))
    }

    @Test
    fun certificateMatchesHost_garbageDer_isFalse() {
        assertFalse(certificateMatchesHost(byteArrayOf(0x30, 0x03, 1, 2), "echalote.test"))
        assertFalse(certificateMatchesHost(ByteArray(0), "echalote.test"))
    }

    // --- Certificate message parsing ---------------------------------------------

    private fun u24(n: Int) = byteArrayOf((n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    private fun certMessage(vararg certs: ByteArray): ByteArray {
        val entries = concatBytes(*certs.map { concatBytes(u24(it.size), it) }.toTypedArray())
        return concatBytes(u24(entries.size), entries)
    }

    @Test
    fun parseCertificateChain_returnsEveryCertificateInOrder() {
        val chain = parseCertificateChain(certMessage(TlsTestCerts.VALID_LEAF, TlsTestCerts.TEST_CA))
        assertEquals(2, chain.size)
        assertContentEquals(TlsTestCerts.VALID_LEAF, chain[0])
        assertContentEquals(TlsTestCerts.TEST_CA, chain[1])
    }

    @Test
    fun parseCertificateChain_rejectsMalformedInput() {
        val leaf = TlsTestCerts.VALID_LEAF
        assertFails { parseCertificateChain(ByteArray(0)) }
        assertFails { parseCertificateChain(byteArrayOf(0, 0)) }
        assertFails { parseCertificateChain(certMessage()) } // empty chain
        assertFails { parseCertificateChain(certMessage(ByteArray(0))) } // zero-length cert
        val good = certMessage(leaf)
        assertFails { parseCertificateChain(good.copyOf(good.size - 1)) } // truncated cert
        assertFails { parseCertificateChain(concatBytes(good, byteArrayOf(0))) } // trailing byte
        val lying = good.copyOf().also { it[2] = (it[2] + 1).toByte() } // outer length too long
        assertFails { parseCertificateChain(lying) }
        val inner = concatBytes(u24(leaf.size + 5), leaf) // inner length past the end
        assertFails { parseCertificateChain(concatBytes(u24(inner.size), inner)) }
        val tooMany = certMessage(*Array(MAX_TLS_CHAIN_CERTS + 1) { byteArrayOf(0x30, 0) })
        assertFails { parseCertificateChain(tooMany) }
    }

    // --- ServerKeyExchange digest -------------------------------------------------

    @Test
    fun serverKeyExchange_acceptsOnlyOfferedSha256AndSha384() {
        val data = "signed".encodeToByteArray()
        assertContentEquals(Sha256.hash(data), serverKeyExchangeDigest(4, data).first)
        assertContentEquals(Sha384.hash(data), serverKeyExchangeDigest(5, data).first)
        assertFailsWith<IllegalArgumentException> { serverKeyExchangeDigest(2, data) } // SHA-1 was never offered
        assertFails { serverKeyExchangeDigest(6, data) }
    }

    // --- ServerHello ---------------------------------------------------------------

    private fun serverHello(
        version: Int = 0x0303,
        sid: ByteArray = ByteArray(32) { 7 },
        compression: Int = 0,
    ): ByteArray {
        val b = ArrayList<Byte>()
        b += (version ushr 8).toByte()
        b += version.toByte()
        repeat(32) { b += 1 }
        b += sid.size.toByte()
        sid.forEach { b += it }
        b += (TLS_ECDHE_RSA_AES256_GCM_SHA384 ushr 8).toByte()
        b += TLS_ECDHE_RSA_AES256_GCM_SHA384.toByte()
        b += compression.toByte()
        return b.toByteArray()
    }

    // --- Scripted server: auth failures before ClientKeyExchange ------------------------

    private fun record(
        type: Int,
        body: ByteArray,
    ): ByteArray = concatBytes(byteArrayOf(type.toByte(), 3, 3, (body.size ushr 8).toByte(), body.size.toByte()), body)

    private fun handshake(
        type: Int,
        body: ByteArray,
    ): ByteArray = concatBytes(byteArrayOf(type.toByte()), u24(body.size), body)

    /** Runs a client against [flight] and returns what it wrote after its ClientHello. */
    private suspend fun rejectedFlight(flight: ByteArray): Pair<Throwable?, ByteArray> {
        val (client, server) = pairedByteDuplexes()
        val tls = TlsClientDuplex("echalote.test", recordTransport = client)
        try {
            server.read(16 * 1024) // ClientHello
            server.write(record(22, flight))
            val error = runCatching { tls.ready.await() }.exceptionOrNull()
            return error to server.read(16)
        } finally {
            tls.close()
        }
    }

    @Test
    fun malformedCertificateMessage_isTlsCertificateError_withDecodeErrorAlert() =
        runTest {
            val flight = concatBytes(handshake(2, serverHello()), handshake(11, u24(0)))
            val (error, sent) = rejectedFlight(flight)
            assertTrue(error is TlsCertificateError, "got $error")
            assertContentEquals(byteArrayOf(21, 3, 3, 0, 2, 2, 50), sent)
        }

    @Test
    fun sha1ServerKeyExchange_isTlsCertificateError_withIllegalParameterAlert() =
        runTest {
            val point = ByteArray(65).also { it[0] = 4 }
            val ske = concatBytes(byteArrayOf(3, 0, 0x17, 65), point, byteArrayOf(2, 1, 0, 2, 9, 9))
            val flight =
                concatBytes(
                    handshake(2, serverHello()),
                    handshake(11, certMessage(TlsTestCerts.VALID_LEAF)),
                    handshake(12, ske),
                    handshake(14, ByteArray(0)),
                )
            val (error, sent) = rejectedFlight(flight)
            assertTrue(error is TlsCertificateError, "got $error")
            assertContentEquals(byteArrayOf(21, 3, 3, 0, 2, 2, 47), sent)
        }

    @Test
    fun serverHello_requiresTls12() {
        assertEquals(32, parseServerHello(serverHello()).sessionId.size)
        assertFails { parseServerHello(serverHello(version = 0x0301)) }
        assertFails { parseServerHello(serverHello(version = 0x0302)) }
        assertFails { parseServerHello(serverHello(version = 0x0304)) }
    }

    @Test
    fun serverHello_rejectsBadSessionIdAndCompression() {
        assertFails { parseServerHello(serverHello(sid = ByteArray(33))) }
        assertFails { parseServerHello(serverHello(compression = 1)) }
        val truncated = serverHello().copyOf(40)
        assertFails { parseServerHello(truncated) }
    }

    // --- WebPKI entry point ------------------------------------------------------

    @Test
    fun webPki_withoutHostName_failsClosed() =
        runTest {
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(listOf(TlsTestCerts.VALID_LEAF), null) }
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(listOf(TlsTestCerts.VALID_LEAF), "") }
            assertFailsWith<TlsCertificateError> { verifyWebPkiChain(emptyList(), "echalote.test") }
        }

    @Test
    fun webPki_rejectsUntrustedChainWithoutAnchors() =
        runTest {
            setTlsTrustAnchorsForTesting(null)
            assertFailsWith<TlsCertificateError> {
                verifyWebPkiChain(listOf(TlsTestCerts.VALID_LEAF, TlsTestCerts.TEST_CA), "echalote.test")
            }
        }

    // --- Session cache isolation -------------------------------------------------

    @Test
    fun torLink_neverOffersCachedSession() =
        runTest {
            resetTlsSessionCache()
            val ticket = "cached-ticket-for-weblink".encodeToByteArray()
            rememberTlsSession(
                TlsResumption(
                    host = "relay.example",
                    master = ByteArray(48) { 1 },
                    sessionId = ByteArray(0),
                    ticket = ticket,
                    ems = true,
                    expiresAtMs = Long.MAX_VALUE,
                ),
            )
            val tls = TlsClientDuplex("relay.example", trust = TlsTrust.TorLink)
            try {
                val rec = tls.inner.read(16 * 1024)
                assertFalse(containsBytes(rec, ticket), "TorLink must not resume a WebPKI session")
                assertTrue(lookupTlsSession("relay.example") != null)
            } finally {
                tls.close()
                resetTlsSessionCache()
            }
        }

    @Test
    fun changingTrustAnchors_dropsCachedSessions() {
        rememberTlsSession(
            TlsResumption(
                host = "echalote.test",
                master = ByteArray(48),
                sessionId = ByteArray(32) { 1 },
                ticket = ByteArray(0),
                ems = true,
                expiresAtMs = Long.MAX_VALUE,
            ),
        )
        setTlsTrustAnchorsForTesting(listOf(TlsTestCerts.TEST_CA))
        assertNull(lookupTlsSession("echalote.test"))
        setTlsTrustAnchorsForTesting(null)
    }

    private fun containsBytes(
        haystack: ByteArray,
        needle: ByteArray,
    ): Boolean = (0..haystack.size - needle.size).any { i -> haystack.copyOfRange(i, i + needle.size).contentEquals(needle) }
}
