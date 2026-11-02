package io.bluewallet.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DirCacheTest {
    private class FakeCache(
        val failWrites: Boolean = false,
        val failReads: Boolean = false,
    ) : TorDirCache {
        val files = HashMap<String, ByteArray>()
        val reads = ArrayList<String>()
        val writes = ArrayList<String>()
        val deletes = ArrayList<String>()

        override suspend fun read(key: String): ByteArray? {
            reads += key
            if (failReads) error("disk on fire")
            return files[key]?.copyOf()
        }

        override suspend fun write(
            key: String,
            bytes: ByteArray,
        ) {
            writes += key
            if (failWrites) error("disk full")
            files[key] = bytes.copyOf()
        }

        override suspend fun delete(key: String) {
            deletes += key
            files.remove(key)
        }
    }

    private class Net(
        val consensus: () -> String = { fixtureConsensusText },
    ) {
        val consensusUrls = ArrayList<String>()
        val keyUrls = ArrayList<String>()
        val engine =
            HttpEngine { _, url, _, _, _, _ ->
                if (url.contains("/tor/keys/")) {
                    keyUrls += url
                    HttpResponse(200, fixtureKeysText.encodeToByteArray())
                } else {
                    consensusUrls += url
                    HttpResponse(200, consensus().encodeToByteArray())
                }
            }
        val calls get() = consensusUrls.size + keyUrls.size
    }

    private val validUntil get() = requireNotNull(fixtureConsensus.validUntilMillis)

    /** One "process": a fresh cert store and an empty in-memory consensus cache. */
    private suspend fun bootstrap(
        net: Net,
        cache: TorDirCache,
        now: Long = FIXTURE_NOW,
        store: AuthorityCertStore = AuthorityCertStore(),
    ): Consensus {
        resetCachedConsensus()
        return fetchOnce(net, cache, now, store)
    }

    private suspend fun fetchOnce(
        net: Net,
        cache: TorDirCache,
        now: Long,
        store: AuthorityCertStore,
    ) = fetchVerifiedMicrodescConsensus(
        source = ConsensusSource(listOf("http://a/c"), listOf("127.0.0.1:1"), net.engine, concurrency = 1, cache = cache),
        trust = ConsensusTrust(DirectoryAuthorities.V3_IDENTITIES, store, now = { now }),
    )

    private suspend fun populated(): FakeCache {
        val cache = FakeCache()
        bootstrap(Net(), cache)
        assertNotNull(cache.files[TorDirCache.CONSENSUS_MICRODESC])
        assertNotNull(cache.files[TorDirCache.AUTHORITY_CERTS])
        return cache
    }

    @AfterTest
    fun reset() {
        resetCachedConsensus()
    }

    @Test
    fun defaultIsNoOpAndEveryColdStartDownloads() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            assertSame(TorDirCache.None, Echalote.dirCache)
            assertSame(TorDirCache.None, ConsensusSource(emptyList(), emptyList(), Net().engine).cache)
            val net = Net()
            bootstrap(net, TorDirCache.None)
            bootstrap(net, TorDirCache.None)
            assertEquals(2, net.consensusUrls.size)
            assertEquals(2, net.keyUrls.size)
        }

    @Test
    fun secondColdStartUsesTheDiskCacheWithoutAnyNetworkFetch() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = FakeCache()
            val first = Net()
            bootstrap(first, cache)
            assertEquals(1, first.consensusUrls.size)
            assertEquals(1, first.keyUrls.size)
            assertContentEquals(fixtureConsensusText.encodeToByteArray(), cache.files[TorDirCache.CONSENSUS_MICRODESC])
            val certText = cache.files.getValue(TorDirCache.AUTHORITY_CERTS).decodeToString()
            assertTrue(AuthorityKeyCertParser.parseAll(certText).size >= fixtureConsensus.signatures.size)

            val second = Net()
            val got = bootstrap(second, cache)
            assertEquals(0, second.calls, "consensus=${second.consensusUrls} keys=${second.keyUrls}")
            assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
            assertEquals(fixtureConsensus.microdescs.size, got.microdescs.size)
            assertSame(got, cachedConsensus?.second, "a fresh disk copy goes into the memory cache")
            assertTrue(cache.deletes.isEmpty(), "${cache.deletes}")
        }

    @Test
    fun cachedCertsAloneSaveTheKeyFetch() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            cache.files.remove(TorDirCache.CONSENSUS_MICRODESC)
            val net = Net()
            bootstrap(net, cache)
            assertEquals(1, net.consensusUrls.size)
            assertEquals(0, net.keyUrls.size)
        }

    @Test
    fun consensusPastTheReasonablyLiveWindowIsDeletedAndRefetched() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val net = Net()
            val tooLate = validUntil + CONSENSUS_REASONABLY_LIVE_MS + 1
            // The network copy is the same (now too old) document, so the fetch fails too.
            assertFails { bootstrap(net, cache, now = tooLate) }
            assertTrue(TorDirCache.CONSENSUS_MICRODESC in cache.deletes, "${cache.deletes}")
            assertNull(cache.files[TorDirCache.CONSENSUS_MICRODESC])
            assertEquals(1, net.consensusUrls.size)
        }

    @Test
    fun tamperedCachedConsensusIsRejectedDeletedAndReplacedByAFetch() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val tampered = fixtureConsensusText.replaceFirst("\nw Bandwidth=", "\nw Bandwidth=9")
            cache.files[TorDirCache.CONSENSUS_MICRODESC] = tampered.encodeToByteArray()
            val net = Net()
            val got = bootstrap(net, cache)
            assertTrue(TorDirCache.CONSENSUS_MICRODESC in cache.deletes, "${cache.deletes}")
            assertEquals(1, net.consensusUrls.size)
            assertEquals(fixtureConsensus.microdescs, got.microdescs)
            assertContentEquals(fixtureConsensusText.encodeToByteArray(), cache.files[TorDirCache.CONSENSUS_MICRODESC])
        }

    @Test
    fun truncatedOrGarbageCachedConsensusFallsBackToAFetch() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val full = fixtureConsensusText.encodeToByteArray()
            for (bad in listOf(full.copyOf(full.size / 2), byteArrayOf(0, 1, 2, -1), ByteArray(0))) {
                cache.files[TorDirCache.CONSENSUS_MICRODESC] = bad
                cache.deletes.clear()
                val net = Net()
                bootstrap(net, cache)
                assertEquals(listOf(TorDirCache.CONSENSUS_MICRODESC), cache.deletes)
                assertEquals(1, net.consensusUrls.size)
            }
        }

    @Test
    fun forgedCachedCertIsDroppedTheFileDeletedAndTheCertsRefetched() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val certs = cache.files.getValue(TorDirCache.AUTHORITY_CERTS).decodeToString()
            // Flip one base64 character inside the first certification signature.
            val sigAt = certs.indexOf("-----BEGIN SIGNATURE-----\n") + "-----BEGIN SIGNATURE-----\n".length + 5
            val flipped = if (certs[sigAt] == 'A') 'B' else 'A'
            cache.files[TorDirCache.AUTHORITY_CERTS] = (certs.substring(0, sigAt) + flipped + certs.substring(sigAt + 1)).encodeToByteArray()
            val net = Net()
            bootstrap(net, cache)
            assertTrue(TorDirCache.AUTHORITY_CERTS in cache.deletes, "${cache.deletes}")
            assertEquals(0, net.consensusUrls.size, "the cached consensus is still good")
            assertEquals(1, net.keyUrls.size, "the dropped cert is fetched again")
            assertEquals(
                AuthorityKeyCertParser.parseAll(certs).map { it.raw }.toSet(),
                AuthorityKeyCertParser.parseAll(cache.files.getValue(TorDirCache.AUTHORITY_CERTS).decodeToString()).map { it.raw }.toSet(),
            )
        }

    @Test
    fun garbageCachedCertsAreDeletedAndRefetched() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val certs = cache.files.getValue(TorDirCache.AUTHORITY_CERTS).decodeToString()
            for (bad in listOf("dir-key-certificate-version 3\nfingerprint zz\n", certs.substring(0, certs.length / 2), "\u0000\u00ff")) {
                cache.files[TorDirCache.AUTHORITY_CERTS] = bad.encodeToByteArray()
                cache.deletes.clear()
                val net = Net()
                bootstrap(net, cache)
                assertEquals(0, net.consensusUrls.size)
                assertEquals(1, net.keyUrls.size)
                if (bad.contains("dir-key-certificate-version")) assertTrue(TorDirCache.AUTHORITY_CERTS in cache.deletes, bad.take(40))
                assertEquals(
                    AuthorityKeyCertParser.parseAll(certs).size,
                    AuthorityKeyCertParser.parseAll(cache.files.getValue(TorDirCache.AUTHORITY_CERTS).decodeToString()).size,
                )
            }
        }

    @Test
    fun reasonablyLiveConsensusIsServedAndRefreshedInTheBackground() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            val net = Net()
            val stale = validUntil + 60 * 60 * 1000L
            val store = AuthorityCertStore()
            resetCachedConsensus()
            val got = fetchOnce(net, cache, stale, store)
            assertEquals(fixtureConsensus.validAfterMillis, got.validAfterMillis)
            assertNull(cachedConsensus, "a stale copy never enters the fresh memory cache")
            // A second caller gets the same verified copy without re-reading the disk.
            val reads = cache.reads.size
            assertSame(got, fetchOnce(net, cache, stale, store))
            assertEquals(reads, cache.reads.size)
            awaitDirRefresh()
            assertEquals(1, net.consensusUrls.size, "one background refresh, not one per caller")
            assertFalse(TorDirCache.CONSENSUS_MICRODESC in cache.deletes)
        }

    @Test
    fun cacheFailuresNeverBreakTor() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val writes = FakeCache(failWrites = true)
            val net = Net()
            bootstrap(net, writes)
            assertEquals(listOf(TorDirCache.AUTHORITY_CERTS, TorDirCache.CONSENSUS_MICRODESC), writes.writes)
            bootstrap(net, writes)
            assertEquals(2, net.consensusUrls.size)

            val reads = FakeCache(failReads = true)
            bootstrap(net, reads)
            assertEquals(3, net.consensusUrls.size)
        }

    @Test
    fun concurrentColdStartsVerifyTheCachedCopyOnce() =
        runTest(timeout = RSA_TEST_TIMEOUT) {
            val cache = populated()
            cache.reads.clear()
            resetCachedConsensus()
            val net = Net()
            val store = AuthorityCertStore()
            val got = List(3) { async { fetchOnce(net, cache, FIXTURE_NOW, store) } }.awaitAll()
            assertEquals(0, net.calls)
            assertEquals(1, cache.reads.count { it == TorDirCache.CONSENSUS_MICRODESC }, "${cache.reads}")
            assertTrue(got.all { it === got[0] })
        }
}
