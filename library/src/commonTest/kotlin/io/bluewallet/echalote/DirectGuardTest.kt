package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DirectGuardTest {
    private class MemCache : TorDirCache {
        val files = HashMap<String, ByteArray>()

        override suspend fun read(key: String) = files[key]?.copyOf()

        override suspend fun write(
            key: String,
            bytes: ByteArray,
        ) {
            files[key] = bytes.copyOf()
        }

        override suspend fun delete(key: String) {
            files.remove(key)
        }
    }

    private val saved = torDirCache

    @AfterTest
    fun restore() {
        torDirCache = saved
    }

    private fun head(
        id: String,
        flags: List<String> = listOf("Fast", "Guard", "Running", "Stable", "Valid"),
        orport: Int = 9001,
        bw: String = "1000",
    ) = MicrodescHead(
        nickname = id,
        identity = id,
        date = "2026-01-01",
        hour = "00:00:00",
        hostname = "10.0.0.1",
        orport = orport,
        dirport = 0,
        microdesc = "m",
        flags = flags,
        entries = emptyMap(),
        bandwidth = mapOf("Bandwidth" to bw),
    )

    @Test
    fun relayIdentityIsSha1OfPkcs1KeyNotOfSpki() {
        // Independently computed: openssl rsa -pubin -RSAPublicKey_out -outform der | sha1
        // (it also equals the leaf's subjectKeyIdentifier). SHA-1 of the whole SPKI is ee726faf....
        val cert = RsaCert(1, TlsTestCerts.VALID_LEAF, X509Certificate.parse(TlsTestCerts.VALID_LEAF))
        assertEquals("d454485c5b438d6a8a789fd1ba812a5b29e1d045", cert.sha1OrThrow().toHexString())
    }

    @Test
    fun onlyStableNonExitGuardsAreCandidates() {
        assertTrue(isDirectGuardCandidate(head("a")))
        assertTrue(!isDirectGuardCandidate(head("b", flags = listOf("Fast", "Guard", "Running", "Stable", "Valid", "Exit"))))
        assertTrue(!isDirectGuardCandidate(head("c", flags = listOf("Fast", "Running", "Stable", "Valid"))))
        assertTrue(!isDirectGuardCandidate(head("d", orport = 0)))
    }

    @Test
    fun guardIsPersistedAndReused() =
        runTest {
            val cache = MemCache()
            torDirCache = cache
            val c = Consensus(microdescs = listOf(head("a"), head("b"), head("c")))
            val first = pickDirectGuard(c)
            assertEquals(first.identity, cache.files[DIRECT_GUARD_KEY]?.decodeToString())
            repeat(20) { assertEquals(first.identity, pickDirectGuard(c).identity) }
        }

    @Test
    fun savedGuardGoneFromConsensusPicksAnew() =
        runTest {
            val cache = MemCache()
            torDirCache = cache
            cache.files[DIRECT_GUARD_KEY] = "gone".encodeToByteArray()
            val pick = pickDirectGuard(Consensus(microdescs = listOf(head("a"))))
            assertEquals("a", pick.identity)
            assertEquals("a", cache.files[DIRECT_GUARD_KEY]?.decodeToString())
        }

    @Test
    fun forgetDropsTheSavedGuard() =
        runTest {
            val cache = MemCache()
            torDirCache = cache
            pickDirectGuard(Consensus(microdescs = listOf(head("a"))))
            forgetDirectGuard()
            assertNull(cache.files[DIRECT_GUARD_KEY])
        }

    @Test
    fun noGuardsFails() =
        runTest {
            torDirCache = MemCache()
            assertFailsWith<Exception> { pickDirectGuard(Consensus(microdescs = listOf(head("x", orport = 0)))) }
        }
}
