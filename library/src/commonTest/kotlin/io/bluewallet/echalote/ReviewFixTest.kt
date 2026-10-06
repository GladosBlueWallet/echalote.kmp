package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReviewFixTest {
    @Test
    fun doneEndClosesTheStream() =
        runBlocking {
            val tor = SecretTorClientDuplex()
            try {
                val circ = SecretCircuit(1, tor)
                val stream = SecretTorStreamDuplex("external", 1, circ)
                tor.relayEnd.emit(circ to (stream to RelayEndReasonOther(6)))
                val bytes =
                    withTimeout(1_000) {
                        stream.duplex.read(1)
                    }
                assertEquals(0, bytes.size)
            } finally {
                tor.close()
            }
        }

    @Test
    fun versionZeroCircuitSendmeCreditsTheWindow() {
        val target =
            Target(
                ByteArray(20),
                Sha1.Hasher(),
                Sha1.Hasher(),
                Aes128Ctr128BEKey(Memory(ByteArray(16)), Memory(ByteArray(16))),
                Aes128Ctr128BEKey(Memory(ByteArray(16)), Memory(ByteArray(16))),
            )
        val before = target.packageWindow
        applyCircuitSendme(target, version = 0)
        assertEquals(before + 100, target.packageWindow)
        assertTrue(target.digests.isEmpty())
    }

    @Test
    fun expiredCachedConsensusIsRefetched() =
        runTest {
            val fresh =
                """
                network-status-version 3 microdesc
                vote-status consensus
                consensus-method 35
                valid-after 2000-01-01 00:00:00
                fresh-until 2100-01-01 00:00:00
                valid-until 2100-01-01 00:00:00
                r c0der AjUfyI0L8G9s3lRSZWZB5hGdvX4 2038-01-01 00:00:00 95.216.20.80 8080 0
                m mkHw/LD1moosjemRD+GqSqXzzK1kOvK3ZwTsCPGJIFs
                s Fast Guard Running Stable V2Dir Valid
                pr Link=1-5
                w Bandwidth=1
                directory-footer
                """.trimIndent()
            var calls = 0
            val engine =
                HttpEngine { _, _, _, _, _, _ ->
                    calls += 1
                    HttpResponse(200, fresh.encodeToByteArray())
                }
            try {
                cachedConsensus = currentEpochMillis() to Consensus(validAfterMillis = 0L, validUntilMillis = 1L)
                val got =
                    fetchMicrodescConsensus(
                        force = false,
                        mirrors = listOf("http://127.0.0.1/consensus"),
                        engine = engine,
                    )
                assertEquals(1, calls)
                assertTrue((got.validUntilMillis ?: 0L) > currentEpochMillis())
            } finally {
                resetCachedConsensus()
            }
        }
}
