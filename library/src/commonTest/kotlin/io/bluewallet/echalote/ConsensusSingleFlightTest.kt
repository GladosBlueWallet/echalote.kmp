package io.bluewallet.echalote

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * One shared consensus fetch: concurrent callers join it, the first copy that downloads and
 * verifies wins, and every other in-flight copy is stopped without being waited for.
 */
class ConsensusSingleFlightTest {
    /** Mirror "http://mNNN/c" answers with the genuine consensus after NNN ms (virtual time). */
    private class Mirrors(
        val behave: suspend (url: String) -> String = { url ->
            delay(delayOf(url))
            fixtureConsensusText
        },
    ) {
        val started = ArrayList<String>()
        val cancelled = ArrayList<String>()
        val engine =
            HttpEngine { _, url, _, _, _, _ ->
                if (url.contains("/tor/keys/")) {
                    HttpResponse(200, fixtureKeysText.encodeToByteArray())
                } else {
                    started += url
                    try {
                        HttpResponse(200, behave(url).encodeToByteArray())
                    } catch (e: kotlinx.coroutines.CancellationException) {
                        cancelled += url
                        throw e
                    }
                }
            }

        companion object {
            fun delayOf(url: String): Long =
                Regex("m(\\d+)")
                    .find(url)
                    ?.groupValues
                    ?.get(1)
                    ?.toLong() ?: 0L
        }
    }

    private var verifications = 0

    private fun trust() =
        ConsensusTrust(
            DirectoryAuthorities.V3_IDENTITIES,
            AuthorityCertStore(),
            now = { FIXTURE_NOW },
            verify = { consensus, certs, pinned, now, checkpoint ->
                verifications++
                verifyConsensusSignaturesOrThrow(consensus, certs, pinned, now, checkpoint)
            },
        )

    private fun source(
        mirrors: List<String>,
        m: Mirrors,
        concurrency: Int = 3,
    ) = ConsensusSource(mirrors, listOf("127.0.0.1:1"), m.engine, concurrency)

    private suspend fun fetch(
        mirrors: List<String>,
        m: Mirrors,
        concurrency: Int = 3,
        signal: Abort = Abort(),
        trust: ConsensusTrust = trust(),
    ) = fetchVerifiedMicrodescConsensus(source(mirrors, m, concurrency), trust, force = true, signal = signal)

    @AfterTest
    fun reset() = resetCachedConsensus()

    @Test
    fun parallelCallersShareOneDownloadAndOneVerification() =
        runTest {
            val m = Mirrors()
            val got = List(2) { async { fetch(listOf("http://m100/c"), m, concurrency = 1) } }.awaitAll()
            assertSame(got[0], got[1])
            assertEquals(1, m.started.size, "${m.started}")
            assertEquals(1, verifications)
        }

    @Test
    fun firstVerifiedCopyStopsTheOthersAndOnlyItIsVerified() =
        runTest {
            val m = Mirrors()
            fetch(listOf("http://m100/c", "http://m200/c", "http://m300/c"), m)
            assertEquals(100, currentTime)
            assertEquals(3, m.started.size)
            assertEquals(setOf("http://m200/c", "http://m300/c"), m.cancelled.toSet())
            assertEquals(1, verifications)
        }

    @Test
    fun winnerDoesNotWaitForALoserThatIgnoresCancellation() =
        runTest {
            val m =
                Mirrors { url ->
                    if (url.contains("hang")) withContext(NonCancellable) { delay(30_000) }
                    delay(Mirrors.delayOf(url))
                    fixtureConsensusText
                }
            fetch(listOf("http://m100/c", "http://hang/c"), m)
            assertEquals(100, currentTime)
            assertEquals(1, verifications)
        }

    @Test
    fun copyFailingVerificationFallsThroughToTheNextMirror() =
        runTest {
            val bad = fixtureConsensusText.replaceFirst("\nw Bandwidth=", "\nw Bandwidth=9")
            val m =
                Mirrors { url ->
                    delay(Mirrors.delayOf(url))
                    if (url.contains("bad")) bad else fixtureConsensusText
                }
            val got = fetch(listOf("http://m10bad/c", "http://m500/c"), m, concurrency = 2)
            assertEquals(500, currentTime)
            assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
            assertEquals(2, verifications)
            assertSame(got, cachedConsensus?.second)
        }

    @Test
    fun waiterThatAbortsDetachesWithoutCancellingTheOthers() =
        runTest {
            val m = Mirrors()
            val quitter = Abort()
            val a = async { runCatching { fetch(listOf("http://m1000/c"), m, concurrency = 1, signal = quitter) } }
            val b = async { fetch(listOf("http://m1000/c"), m, concurrency = 1) }
            launch {
                delay(100)
                quitter.abort(Exception("caller left"))
            }
            assertTrue(a.await().isFailure)
            val got = b.await()
            assertEquals(1000, currentTime)
            assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
            assertEquals(1, m.started.size)
            assertTrue(m.cancelled.isEmpty(), "${m.cancelled}")
        }

    @Test
    fun lastWaiterLeavingCancelsTheSharedAttemptAndNothingIsCached() =
        runTest {
            val m = Mirrors()
            val quitter = Abort()
            val a = async { runCatching { fetch(listOf("http://m1000/c"), m, concurrency = 1, signal = quitter) } }
            delay(100)
            quitter.abort(Exception("caller left"))
            assertTrue(a.await().isFailure)
            delay(1)
            assertEquals(listOf("http://m1000/c"), m.cancelled)
            assertNull(cachedConsensus)
            fetch(listOf("http://m1000/c"), m, concurrency = 1)
            assertEquals(2, m.started.size)
        }

    @Test
    fun everythingFailingTakesNoLongerThanBeforeAndIsSharedByAllCallers() =
        runTest {
            // Before: each caller raced the six mirrors three at a time: two 30 s rounds = 60 s.
            val m =
                Mirrors { _ ->
                    delay(30_000)
                    error("timed out")
                }
            val mirrors = List(6) { "http://dead$it/c" }
            val results = List(2) { async { runCatching { fetch(mirrors, m) } } }.awaitAll()
            assertTrue(results.all { it.isFailure })
            assertEquals(60_000, currentTime)
            assertEquals(6, m.started.size)
            assertNull(cachedConsensus)
            assertEquals(0, verifications)
        }

    @Test
    fun signatureVerificationStopsAtTheCheckpoint() {
        var checks = 0
        val err =
            assertFails {
                // No certificates, so every checkpoint call comes from the per-signature loop.
                verifyConsensusSignaturesOrThrow(fixtureConsensus, emptyList(), DirectoryAuthorities.V3_IDENTITIES, FIXTURE_NOW) {
                    checks++
                    if (checks == 2) error("stop")
                }
            }
        assertEquals("stop", err.message)
        assertEquals(2, checks)
    }
}
