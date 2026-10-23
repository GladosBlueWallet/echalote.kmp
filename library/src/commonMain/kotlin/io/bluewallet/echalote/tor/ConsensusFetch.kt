package io.bluewallet.echalote

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Where to download the consensus and the authority key certificates from. */
internal class ConsensusSource(
    val mirrors: List<String>,
    val authorityHosts: List<String>,
    val engine: HttpEngine,
    val concurrency: Int = 3,
)

/** What to trust: the pinned authority identities, verified certificates, and the clock. */
internal class ConsensusTrust(
    val pinned: Set<String> = DirectoryAuthorities.V3_IDENTITIES,
    val store: AuthorityCertStore = defaultAuthorityCertStore,
    val now: () -> Long = ::currentEpochMillis,
    val verify: ConsensusVerifier = ::verifyConsensusSignaturesOrThrow,
)

/** Signature check used by [ConsensusTrust]; a seam for tests. */
internal typealias ConsensusVerifier = (
    consensus: Consensus,
    certs: Collection<AuthorityKeyCert>,
    pinned: Set<String>,
    now: Long,
    checkpoint: () -> Unit,
) -> Set<String>

private fun <T> List<T>.secureShuffled(): List<T> {
    val out = toMutableList()
    for (i in out.size - 1 downTo 1) {
        val j = randomIndex(i + 1)
        val t = out[i]
        out[i] = out[j]
        out[j] = t
    }
    return out
}

private const val KEY_FETCH_TIMEOUT_MS = 10_000L
private const val CONSENSUS_FETCH_TIMEOUT_MS = 30_000L

/**
 * GETs [path] from the authorities, one at a time, and returns the first body that holds key
 * certificates. The response is ~20 KB, so a short timeout is enough.
 */
private suspend fun fetchAuthorityKeys(
    path: String,
    source: ConsensusSource,
    signal: Abort,
): String =
    fetchFirstOk(
        source.authorityHosts.secureShuffled(),
        worker = { host, race ->
            race.throwIfAborted()
            val started = timeMark()
            val res = withAbort(race) { source.engine.call("GET", "http://$host$path", timeoutMs = KEY_FETCH_TIMEOUT_MS) }
            println(
                "echalote.consensus keys host=$host status=${res.status} bytes=${res.body.size} " +
                    "ms=${started.elapsedNow().inWholeMilliseconds}",
            )
            check(res.status in 200..299) { "key certificates HTTP ${res.status}" }
            val text = res.body.decodeToString()
            check(text.contains("dir-key-certificate-version ")) { "no key certificates from $host" }
            text
        },
        concurrency = 1,
        signal = signal,
    )

/**
 * Downloads one mirror's consensus and returns it only if it is fresh and properly signed.
 * [race] is checked between every stage and between signature checks, so a copy that lost
 * the race stops instead of burning CPU.
 */
private suspend fun downloadVerifiedConsensus(
    url: String,
    source: ConsensusSource,
    trust: ConsensusTrust,
    race: Abort,
): Consensus {
    val copy = "copy=${url.substringAfter("://").substringBefore('/')}"
    val started = timeMark()
    race.throwIfAborted()
    val res =
        timed("consensus", "http", { copy }) {
            withAbort(race) { source.engine.call("GET", url, timeoutMs = CONSENSUS_FETCH_TIMEOUT_MS) }
        }
    check(res.status in 200..299) { "HTTP ${res.status}" }
    race.throwIfAborted()
    val text = timed("consensus", "decode", { "$copy bytes=${res.body.size}" }) { res.body.decodeToString() }
    timed("consensus", "footer-check", { copy }) {
        check(text.contains("directory-footer")) { "truncated consensus (no directory-footer)" }
    }
    race.throwIfAborted()
    val parsed = timed("consensus", "parse", { copy }) { ConsensusParser.parseOrThrow(text) }
    check(parsed.microdescs.isNotEmpty()) { "consensus has no microdescs" }
    race.throwIfAborted()
    timed("consensus", "fresh", { copy }) { parsed.ensureFresh(trust.now()) }
    race.throwIfAborted()
    val downloaded = started.elapsedNow()
    val checkpoint = { race.throwIfAborted() }
    val signers =
        runCatching {
            val certs =
                timed("consensus", "certs", { copy }) {
                    trust.store.certsFor(parsed, trust.pinned, trust.now(), checkpoint) { path -> fetchAuthorityKeys(path, source, race) }
                }
            race.throwIfAborted()
            timed("consensus", "verify-signatures", { copy }) { trust.verify(parsed, certs, trust.pinned, trust.now(), checkpoint) }
        }.onFailure { println("echalote.consensus rejected url=$url ${it.message}") }
            .getOrThrow()
    val total = started.elapsedNow()
    logTiming("consensus", "copy-total", total, "$copy verified=true")
    println(
        "echalote.consensus verified sigs=${signers.size}/${trust.pinned.size} " +
            "need=${DirectoryAuthorities.MIN_VALID_SIGNATURES} by=${signers.sorted().joinToString(",") { it.take(8) }} " +
            "bytes=${res.body.size} downloadMs=${downloaded.inWholeMilliseconds} " +
            "verifyMs=${(total - downloaded).inWholeMilliseconds} url=$url",
    )
    return parsed
}

/** Races the mirrors (with failover) and caches the first copy that verifies. */
private suspend fun raceMirrors(
    source: ConsensusSource,
    trust: ConsensusTrust,
    signal: Abort,
): Consensus {
    val consensus =
        fetchFirstOk(
            source.mirrors.secureShuffled(),
            worker = { url, race ->
                runCatching { downloadVerifiedConsensus(url, source, trust, race) }
                    .onFailure { if (race.aborted) println("echalote.consensus cancelled url=$url reason=${race.reason?.message}") }
                    .getOrThrow()
            },
            concurrency = source.concurrency,
            signal = signal,
        )
    cachedConsensus = trust.now() to consensus
    return consensus
}

/** One consensus download shared by every concurrent caller with the same mirrors. */
private class SharedConsensusFetch(
    val key: List<Any>,
    val result: Deferred<Consensus>,
    val abort: Abort,
    val scope: CoroutineScope,
) {
    var waiters = 0
}

private val sharedFetchLock = Mutex()
private var sharedFetch: SharedConsensusFetch? = null

private suspend fun joinSharedFetch(
    source: ConsensusSource,
    trust: ConsensusTrust,
): SharedConsensusFetch =
    sharedFetchLock.withLock {
        val key = listOf(source.mirrors, source.authorityHosts, trust.pinned)
        val shared =
            sharedFetch?.takeIf { it.key == key && it.result.isActive } ?: run {
                val abort = Abort()
                val scope = CoroutineScope(currentCoroutineContext().minusKey(Job) + SupervisorJob())
                val result = scope.async { raceMirrors(source, trust, abort) }
                println("echalote.consensus single-flight start")
                SharedConsensusFetch(key, result, abort, scope).also { sharedFetch = it }
            }
        shared.waiters += 1
        shared
    }

private suspend fun leaveSharedFetch(shared: SharedConsensusFetch) =
    withContext(NonCancellable) {
        sharedFetchLock.withLock {
            shared.waiters -= 1
            val finished = shared.result.isCompleted
            if (shared.waiters == 0 || finished) {
                if (sharedFetch === shared) sharedFetch = null
            }
            if (shared.waiters == 0 && !finished) {
                println("echalote.consensus single-flight cancelled (no waiters left)")
                shared.abort.abort(CancellationException("consensus fetch: no waiters left"))
                shared.scope.cancel()
            }
        }
    }

/**
 * Downloads the microdesc consensus and accepts it only if it is fresh and carries valid
 * signatures from at least [DirectoryAuthorities.MIN_VALID_SIGNATURES] distinct pinned
 * authorities. A mirror that fails either check is skipped; if every mirror fails, this throws
 * and nothing is cached.
 *
 * Concurrent callers share one attempt (single-flight). [signal] only detaches this caller;
 * the attempt is cancelled once every caller has left. [force] skips the cache but still joins
 * an attempt that is already running, since that one is fresh too.
 */
internal suspend fun fetchVerifiedMicrodescConsensus(
    source: ConsensusSource,
    trust: ConsensusTrust,
    force: Boolean = false,
    signal: Abort = Abort(),
): Consensus {
    val progress = fetchProgress()
    progress?.report(FetchStage.DOWNLOADING_DIRECTORY)
    val started = trust.now()
    val cached = cachedConsensus
    if (!force && cached != null && started - cached.first < CONSENSUS_CACHE_MS) {
        val stillValid =
            try {
                cached.second.ensureFresh(started)
                true
            } catch (_: IllegalStateException) {
                false
            }
        if (stillValid) {
            println("echalote.consensus cache-hit ageMs=${started - cached.first}")
            progress?.report(FetchStage.DOWNLOADING_DIRECTORY, 1.0)
            return cached.second
        }
        cachedConsensus = null
    }
    signal.throwIfAborted()
    val waitStart = timeMark()
    val shared = joinSharedFetch(source, trust)
    var outcome = "error"
    try {
        val consensus = withAbort(signal) { shared.result.await() }
        outcome = "ok"
        progress?.report(FetchStage.DOWNLOADING_DIRECTORY, 1.0)
        return consensus
    } finally {
        leaveSharedFetch(shared)
        logTiming("consensus", "caller-wait", waitStart.elapsedNow(), "outcome=$outcome")
    }
}
