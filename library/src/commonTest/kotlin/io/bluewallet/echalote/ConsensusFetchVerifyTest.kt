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
        runTest {
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
        runTest {
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
        runTest {
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
        runTest {
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
}
