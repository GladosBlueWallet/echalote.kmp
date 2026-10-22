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
            var calls = 0
            val engine =
                HttpEngine { _, url, _, _, _, _ ->
                    if (url.contains("/tor/keys/")) {
                        HttpResponse(200, fixtureKeysText.encodeToByteArray())
                    } else {
                        calls += 1
                        HttpResponse(200, fixtureConsensusText.encodeToByteArray())
                    }
                }
            try {
                cachedConsensus = FIXTURE_NOW to Consensus(validAfterMillis = 0L, validUntilMillis = 1L)
                val got =
                    fetchVerifiedMicrodescConsensus(
                        source = ConsensusSource(listOf("http://127.0.0.1/consensus"), listOf("127.0.0.1:1"), engine, 1),
                        trust = ConsensusTrust(DirectoryAuthorities.V3_IDENTITIES, AuthorityCertStore(), { FIXTURE_NOW }),
                        force = false,
                    )
                assertEquals(1, calls)
                assertTrue((got.validUntilMillis ?: 0L) > FIXTURE_NOW)
            } finally {
                resetCachedConsensus()
            }
        }
}
