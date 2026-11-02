package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ConsensusFetchVerifyTest {
    private val tampered: String by lazy {
        fixtureConsensusText.replaceFirst("\nw Bandwidth=", "\nw Bandwidth=9")
    }

    private class Recorder(
        val consensus: (String) -> String,
        val keys: () -> String = { fixtureKeysText },
    ) {
        val consensusUrls = ArrayList<String>()
        val keyUrls = ArrayList<String>()
        val engine =
            HttpEngine { _, url, _, _, _, _ ->
                if (url.contains("/tor/keys/")) {
                    keyUrls += url
                    HttpResponse(200, keys().encodeToByteArray())
                } else {
                    consensusUrls += url
                    HttpResponse(200, consensus(url).encodeToByteArray())
                }
            }
    }

    private suspend fun fetch(
        rec: Recorder,
        store: AuthorityCertStore,
        mirrors: List<String>,
    ) = fetchVerifiedMicrodescConsensus(
        source = ConsensusSource(mirrors, listOf("127.0.0.1:1"), rec.engine, concurrency = 1),
        trust = ConsensusTrust(DirectoryAuthorities.V3_IDENTITIES, store, now = { FIXTURE_NOW }),
        force = true,
    )

    @Test
    fun badlySignedConsensusMovesToNextMirrorAndOnlyTheVerifiedOneIsCached() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val rec = Recorder({ url -> if (url.contains("bad")) tampered else fixtureConsensusText })
            try {
                val got = fetch(rec, AuthorityCertStore(), listOf("http://bad/c", "http://good/c"))
                assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
                assertSame(got, cachedConsensus?.second)
                assertTrue(rec.consensusUrls.last().contains("good"), "${rec.consensusUrls}")
            } finally {
                resetCachedConsensus()
            }
        }

    @Test
    fun everyMirrorBadlySignedFailsClosedAndCachesNothing() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val rec = Recorder({ tampered })
            try {
                val err = assertFails { fetch(rec, AuthorityCertStore(), listOf("http://a/c", "http://b/c")) }
                assertEquals(2, rec.consensusUrls.size)
                val all = err.toString() + (err as? AggregateError)?.errors?.joinToString { it.toString() }
                assertTrue(all.contains("valid authority signatures"), all)
                assertNull(cachedConsensus)
            } finally {
                resetCachedConsensus()
            }
        }

    @Test
    fun unreachableKeyCertsFailClosed() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val rec = Recorder({ fixtureConsensusText }, keys = { "" })
            try {
                assertFails { fetch(rec, AuthorityCertStore(), listOf("http://a/c")) }
                assertNull(cachedConsensus)
            } finally {
                resetCachedConsensus()
            }
        }

    @Test
    fun keyCertsComeFromAuthoritiesByFingerprintAndSigningKeyAndAreCached() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val rec = Recorder({ fixtureConsensusText })
            val store = AuthorityCertStore()
            try {
                fetch(rec, store, listOf("http://a/c"))
                fetch(rec, store, listOf("http://a/c"))
                assertEquals(1, rec.keyUrls.size, "${rec.keyUrls}")
                val url = rec.keyUrls.single()
                assertTrue(url.startsWith("http://127.0.0.1:1/tor/keys/fp-sk/"), url)
                for (sig in fixtureConsensus.signatures) {
                    assertTrue(url.contains("${sig.identity}-${sig.signingKeyDigest}"), url)
                }
            } finally {
                resetCachedConsensus()
            }
        }

    /** Parallel copies: verification runs one copy at a time, and stops at the first good one. */
    private suspend fun racedVerifyCount(badFirst: Boolean): Pair<Int, Consensus> {
        val delays = mapOf("a" to 100L, "b" to 200L, "c" to 300L)
        val engine =
            HttpEngine { _, url, _, _, _, _ ->
                if (url.contains("/tor/keys/")) {
                    HttpResponse(200, fixtureKeysText.encodeToByteArray())
                } else {
                    val host = url.substringAfter("://").substringBefore('/')
                    kotlinx.coroutines.delay(delays.getValue(host))
                    val text = if (badFirst && host == "a") tampered else fixtureConsensusText
                    HttpResponse(200, text.encodeToByteArray())
                }
            }
        var verified = 0
        val trust =
            ConsensusTrust(
                DirectoryAuthorities.V3_IDENTITIES,
                AuthorityCertStore(),
                now = { FIXTURE_NOW },
                verify = { c, certs, pinned, now, cp ->
                    verified += 1
                    verifyConsensusWithStoreCerts(c, certs, pinned, now, cp)
                },
            )
        val got =
            fetchVerifiedMicrodescConsensus(
                source = ConsensusSource(listOf("http://a/c", "http://b/c", "http://c/c"), listOf("127.0.0.1:1"), engine, concurrency = 3),
                trust = trust,
                force = true,
            )
        return verified to got
    }

    @Test
    fun parallelCopiesAreVerifiedOnceWhenTheFirstIsGood() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            try {
                val (verified, got) = racedVerifyCount(badFirst = false)
                assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
                assertEquals(1, verified)
            } finally {
                resetCachedConsensus()
            }
        }

    @Test
    fun aBadFirstCopyFallsBackToTheNextArrivedCopy() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            try {
                val (verified, got) = racedVerifyCount(badFirst = true)
                assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
                assertSame(got, cachedConsensus?.second)
                assertEquals(2, verified)
            } finally {
                resetCachedConsensus()
            }
        }
}
