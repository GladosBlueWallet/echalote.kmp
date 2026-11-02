package io.bluewallet.echalote

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * A consensus loaded from the disk cache that is past its valid-until but still "reasonably
 * live" (see [CONSENSUS_REASONABLY_LIVE_MS]). It is served, already verified, while a
 * background refresh runs, so callers do not re-verify it from disk each time. Guarded by
 * [diskLock]; cleared once a fresh consensus is fetched.
 */
private var staleConsensus: Pair<List<Any>, Consensus>? = null

/** Serializes disk loads, so concurrent cold starts verify the cached copy only once. */
private val diskLock = Mutex()

/** The background refresh started for a stale cached consensus; guarded by [diskLock]. */
private var refreshJob: Job? = null
private var lastRefreshFailedAt: Long? = null
private const val REFRESH_RETRY_MS = 60_000L

/** Where background refreshes run; replaced in tests. */
internal var dirRefreshScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

/** Forgets the stale disk copy once a fresh consensus has been fetched. */
internal suspend fun clearStaleConsensus() {
    diskLock.withLock { staleConsensus = null }
}

internal fun resetDiskConsensusState() {
    staleConsensus = null
    refreshJob = null
    lastRefreshFailedAt = null
}

/** Waits for a running background refresh, if any (tests). */
internal suspend fun awaitDirRefresh() {
    diskLock.withLock { refreshJob }?.join()
}

private fun diskKey(
    source: ConsensusSource,
    trust: ConsensusTrust,
): List<Any> = listOf(source.mirrors, source.authorityHosts, trust.pinned, source.cache)

private fun Consensus.isWithin(
    now: Long,
    grace: Long,
): Boolean {
    val after = validAfterMillis
    val until = validUntilMillis
    return after != null && until != null && now >= after && now <= until + grace
}

private fun Consensus.isUsable(now: Long): Boolean = isWithin(now, CONSENSUS_REASONABLY_LIVE_MS)

private fun Consensus.isFresh(now: Long): Boolean = isWithin(now, 0L)

/**
 * Returns a verified consensus from the disk cache, or null if there is none worth using.
 * A fresh one goes into the in-memory cache. A reasonably-live one is served while a
 * background refresh fetches a new one. Anything that fails to parse or verify, or that is
 * too old, is deleted.
 */
internal suspend fun consensusFromDisk(
    source: ConsensusSource,
    trust: ConsensusTrust,
    signal: Abort,
): Consensus? =
    diskLock.withLock {
        val now = trust.now()
        // Another caller may have loaded (or fetched) it while this one waited for the lock.
        cachedConsensus?.let { (at, c) -> if (now - at < CONSENSUS_CACHE_MS && c.isFresh(now)) return@withLock c }
        val key = diskKey(source, trust)
        staleConsensus?.let { (k, c) ->
            if (k == key && c.isUsable(now)) {
                maybeRefresh(source, trust, now)
                return@withLock c
            }
            staleConsensus = null
        }
        val loaded = loadVerifiedFromDisk(source, trust, signal) ?: return@withLock null
        val at = trust.now()
        if (loaded.isFresh(at)) {
            cachedConsensus = at to loaded
        } else {
            staleConsensus = key to loaded
            maybeRefresh(source, trust, at)
        }
        loaded
    }

// A failed refresh is logged and retried later; the stale copy keeps serving meanwhile.

/** Starts one background refresh (under [diskLock]); waits a minute after a failed one. */
@Suppress("TooGenericExceptionCaught")
private fun maybeRefresh(
    source: ConsensusSource,
    trust: ConsensusTrust,
    now: Long,
) {
    if (refreshJob?.isActive == true) return
    val failedAt = lastRefreshFailedAt
    if (failedAt != null && now - failedAt in 0 until REFRESH_RETRY_MS) return
    println("echalote.dircache consensus stale; refreshing in background")
    refreshJob =
        dirRefreshScope.launch {
            try {
                fetchVerifiedMicrodescConsensus(source, trust, force = true)
                diskLock.withLock { lastRefreshFailedAt = null }
            } catch (err: CancellationException) {
                throw err
            } catch (err: Exception) {
                println("echalote.dircache background refresh failed ${err.message ?: err}")
                diskLock.withLock { lastRefreshFailedAt = trust.now() }
            }
        }
}

/**
 * Reads the cached consensus and accepts it only after the same checks as a download: it must
 * parse, be within its reasonably-live window, and carry enough valid signatures under
 * (re-verified) authority certificates. On failure the cached copy is deleted.
 *
 * Any failure (bad bytes, parse error, bad signature, cert problem) just means "no usable cached
 * copy"; only cancellation and aborts propagate.
 */
@Suppress("TooGenericExceptionCaught", "ThrowsCount")
private suspend fun loadVerifiedFromDisk(
    source: ConsensusSource,
    trust: ConsensusTrust,
    signal: Abort,
): Consensus? {
    val cache = source.cache
    val started = timeMark()
    val bytes = timed("consensus", "disk-read", { "" }) { cache.readOrNull(TorDirCache.CONSENSUS_MICRODESC) }
    if (bytes == null) {
        println("echalote.dircache consensus miss")
        return null
    }
    val checkpoint = {
        signal.throwIfAborted()
    }
    var certFetchFailed = false
    return try {
        val text = timed("consensus", "decode", { "copy=disk bytes=${bytes.size}" }) { bytes.decodeToString() }
        check(text.contains("directory-footer")) { "truncated consensus (no directory-footer)" }
        checkpoint()
        val parsed = timed("consensus", "parse", { "copy=disk" }) { ConsensusParser.parseOrThrow(text) }
        check(parsed.microdescs.isNotEmpty()) { "consensus has no microdescs" }
        check(parsed.isUsable(trust.now())) { "consensus outside its reasonably-live window" }
        checkpoint()
        val certs =
            timed("consensus", "certs", { "copy=disk" }) {
                try {
                    certsWithDiskCache(parsed, source, trust, signal, checkpoint)
                } catch (err: CancellationException) {
                    throw err
                } catch (err: Exception) {
                    certFetchFailed = !signal.aborted
                    throw err
                }
            }
        checkpoint()
        val signers =
            timed("consensus", "verify-signatures", { "copy=disk" }) {
                trust.verify(parsed, certs, trust.pinned, trust.now(), checkpoint)
            }
        val until = parsed.validUntilMillis ?: 0L
        println(
            "echalote.dircache consensus hit sigs=${signers.size}/${trust.pinned.size} bytes=${bytes.size} " +
                "fresh=${parsed.isFresh(trust.now())} validUntilInMs=${until - trust.now()} " +
                "ms=${started.elapsedNow().inWholeMilliseconds}",
        )
        parsed
    } catch (err: CancellationException) {
        throw err
    } catch (err: Exception) {
        currentCoroutineContext().ensureActive()
        if (signal.aborted) throw err
        println("echalote.dircache consensus rejected ${err.message ?: err}")
        // A cert download that failed says nothing about the cached copy; keep it for next time.
        if (!certFetchFailed) cache.deleteOrLog(TorDirCache.CONSENSUS_MICRODESC)
        null
    }
}
