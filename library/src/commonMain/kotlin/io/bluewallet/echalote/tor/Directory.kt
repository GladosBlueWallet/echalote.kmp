package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

const val DEFAULT_MEEK_URL = "https://1603026938.rsc.cdn77.org/"

class BatchedFetchStream(
    val url: String,
    val sessionId: String,
    private val engine: HttpEngine,
) {
    val duplex = ChannelDuplex()
    private val chunks = ArrayList<ByteArray>()
    private val mutex = Mutex()
    private val data = Channel<Unit>(Channel.CONFLATED)
    var closed = false
    private val job = kotlinx.coroutines.SupervisorJob()
    private val scope = kotlinx.coroutines.CoroutineScope(job + kotlinx.coroutines.Dispatchers.Default)
    private var started = false
    private var posts = 0
    private var pendingSince: TimeMark? = null

    init {
        duplex.onWrite = { bytes ->
            mutex.withLock {
                if (chunks.isEmpty()) pendingSince = timeMark()
                chunks += bytes.copyOf()
            }
            data.trySend(Unit)
        }
        duplex.onClose = {
            closed = true
            job.cancel()
        }
    }

    fun start() {
        if (started) return
        started = true
        scope.launch { loop() }
    }

    private suspend fun takeBody(): ByteArray =
        mutex.withLock {
            if (chunks.isEmpty()) return@withLock ByteArray(0)
            val out = concatBytes(*chunks.toTypedArray())
            chunks.clear()
            out
        }

    private suspend fun loop() {
        var sent = false
        while (!closed) {
            try {
                var body = takeBody()
                if (!sent && body.isEmpty()) {
                    data.receive()
                    if (closed) return
                    continue
                }
                val startedAt = currentEpochMillis()
                val postMark = timeMark()
                val seq = ++posts
                val queuedMs = pendingSince?.elapsedNow()?.msText() ?: "-"
                pendingSince = null
                trace("meek", "post-start") { "seq=$seq up=${body.size} queued=$queuedMs" }
                val res =
                    engine.call(
                        "POST",
                        url,
                        headers = mapOf("x-session-id" to sessionId),
                        body = body,
                        timeoutMs = 30_000,
                    )
                trace("meek", "post-done") {
                    "seq=$seq up=${body.size} down=${res.body.size} ms=${postMark.elapsedNow().msText()} status=${res.status}"
                }
                if (res.status !in 200..299) {
                    error(Exception("meek HTTP ${res.status}"))
                    return
                }
                sent = true
                var i = 0
                while (i < res.body.size) {
                    val n = minOf(16384, res.body.size - i)
                    duplex.enqueue(res.body.copyOfRange(i, i + n))
                    i += n
                }
                if (body.isEmpty() && res.body.isEmpty() && currentEpochMillis() - startedAt < 50) {
                    delay(100)
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
                return
            } catch (e: Throwable) {
                error(e)
                return
            }
        }
    }

    fun error(reason: Throwable) {
        closed = true
        job.cancel()
        duplex.error(reason)
    }
}

fun createMeekStream(
    url: String = DEFAULT_MEEK_URL,
    engine: HttpEngine = defaultHttpEngine(),
): BatchedFetchStream {
    val session = randomUuid()
    return BatchedFetchStream(url, session, engine)
}

data class ExitDialerOptions(
    val meekUrl: String = DEFAULT_MEEK_URL,
    val extendTimeoutMs: Long = 15_000,
    val openTimeoutMs: Long = 20_000,
    val circuitAttempts: Int = 3,
    val circuitRace: Int = 2,
    val http: HttpEngine? = null,
    val maxCircuitAgeMs: Long = 0,
    /**
     * Starts the consensus download (or disk-cache load) as soon as the bridge handshake
     * starts, instead of after the first CREATE_FAST. The circuit build joins the same
     * single-flight fetch, so this only overlaps the two; it never downloads twice.
     */
    val prefetchConsensus: Boolean = true,
    /**
     * Opt-in: connect straight to a guard relay's ORPort (picked from the verified consensus
     * and kept across launches) instead of the meek bridge, falling back to meek if that
     * fails. Much faster, but anyone watching the network sees a Tor connection, and the
     * consensus must be fetched before the first connection. Ignored where there is no
     * socket support (linuxX64 for now); Android, JVM and iOS have it.
     */
    val directGuard: Boolean = false,
    val directConnectTimeoutMs: Long = 5_000,
    /**
     * Link handshake budget once the guard accepted the TCP connection. Its certificate checks
     * run in Kotlin and took 7.4-8 s in a debug build in the iOS simulator on CI, so 8 s made
     * slow devices throw away a working direct connection for the slower meek path.
     */
    val directHandshakeTimeoutMs: Long = 15_000,
) {
    internal var hooks: ExitDialerHooks = ExitDialerHooks()
}

internal class ExitDialerHooks(
    val nowMs: () -> Long = { currentEpochMillis() },
    val ensureTor: (suspend (Abort) -> TorClientDuplex)? = null,
    val makeCircuit: (suspend (TorClientDuplex, Abort) -> Circuit)? = null,
)

private class CachedCircuit(
    val circuit: Circuit,
    val createdAtMs: Long,
)

internal sealed interface Boot {
    data object Retry : Boot

    data object Ready : Boot

    class Wait(
        val deferred: kotlinx.coroutines.Deferred<Unit>,
    ) : Boot
}

internal sealed interface Flight {
    class Hit(
        val circuit: Circuit,
    ) : Flight

    class Join(
        val deferred: CompletableDeferred<Circuit>,
    ) : Flight

    class Lead(
        val deferred: CompletableDeferred<Circuit>,
    ) : Flight
}

internal fun randomIndex(size: Int): Int {
    require(size > 0)
    if (size == 1) return 0
    val bound = size.toLong()
    val space = 0x1_0000_0000L
    val limit = space - (space % bound)
    while (true) {
        val b = secureRandom(4)
        val v =
            ((b[0].toLong() and 0xff) shl 24) or
                ((b[1].toLong() and 0xff) shl 16) or
                ((b[2].toLong() and 0xff) shl 8) or
                (b[3].toLong() and 0xff)
        if (v < limit) return (v % bound).toInt()
    }
}

private val defaultDialerMutex = Mutex()
private var defaultDialer: ExitDialer? = null

/** The [ExitDialerOptions.directGuard] value [defaultDialer] was created with. */
private var defaultDialerDirect = false

internal var directRelayEnabled = false

/** How a Tor connection reached the network: straight to a guard relay, or via the meek bridge. */
internal enum class TorRoute { DIRECT, MEEK }

/** Route of the most recent successful bootstrap in this process (for tests and diagnostics). */
internal var lastBootstrapRoute: TorRoute? = null

/** "nickname host:orport" of the guard the most recent direct bootstrap connected to. */
internal var lastDirectGuard: String? = null

/**
 * The shared dialer behind [Echalote.fetch]. If [directRelayEnabled] no longer matches the mode
 * the current dialer was built with, it is replaced (and the old one disposed), so a mode change
 * made without [setDefaultDirectRelay] still applies to the next new connection.
 */
internal suspend fun defaultExitDialer(): ExitDialer {
    var stale: ExitDialer? = null
    val dialer =
        defaultDialerMutex.withLock {
            val current = defaultDialer
            val wanted = directRelayEnabled
            if (current != null && defaultDialerDirect == wanted) {
                current
            } else {
                stale = current
                createExitDialer(ExitDialerOptions(directGuard = wanted)).also {
                    defaultDialer = it
                    defaultDialerDirect = wanted
                }
            }
        }
    stale?.dispose()
    return dialer
}

/** The default dialer's mode, or null if none exists yet (for tests). */
internal suspend fun defaultDialerDirectMode(): Boolean? = defaultDialerMutex.withLock { defaultDialer?.let { defaultDialerDirect } }

/**
 * Switches direct relay mode for the default client and, if that changes the mode in use,
 * drops the current Tor connection and kept-alive HTTPS sessions so the very next request
 * reconnects the new way. Requests in flight on the old connection fail and are retried by
 * [httpsFetch] on a fresh one; nothing keeps using the old route afterwards.
 */
internal suspend fun setDefaultDirectRelay(enabled: Boolean) {
    val old =
        defaultDialerMutex.withLock {
            val modeChanged = directRelayEnabled != enabled || (defaultDialer != null && defaultDialerDirect != enabled)
            directRelayEnabled = enabled
            if (!modeChanged) return
            defaultDialer.also { defaultDialer = null }
        }
    resetHttpsSessions()
    old?.dispose()
}

internal suspend fun resetDefaultExitDialer() {
    resetHttpsSessions()
    defaultDialerMutex.withLock {
        defaultDialer?.dispose()
        defaultDialer = null
    }
}

internal suspend fun forgetDefaultCircuit(
    host: String,
    port: Int,
) {
    defaultDialerMutex.withLock { defaultDialer }?.forgetCircuit(host, port)
}

interface ExitDialer {
    suspend fun dial(
        host: String,
        port: Int,
        abort: Abort? = null,
        onProgress: FetchProgressListener? = null,
    ): TorStreamDuplex

    /**
     * Like [dial], but returns as soon as RELAY_BEGIN is queued instead of waiting for
     * RELAY_CONNECTED ("optimistic data", as Tor's own client does for exits). Bytes written
     * right away travel in the same round trip as BEGIN; the exit buffers them until it has
     * connected. If the exit refuses, the stream fails with the relay's END reason on the first
     * read instead of here, so callers must treat a read failure like a failed open.
     */
    suspend fun dialOptimistic(
        host: String,
        port: Int,
        abort: Abort? = null,
    ): TorStreamDuplex = dial(host, port, abort)

    suspend fun dispose()

    suspend fun forgetCircuit(
        host: String,
        port: Int,
    ) {
    }
}

class TorStreamDuplex(
    val outer: ByteDuplex,
    private val onClose: () -> Unit = {},
) {
    fun close() {
        onClose()
    }
}

data class BuildExitCircuitOptions(
    val consensusUrls: List<String>? = null,
    val extendTimeoutMs: Long = 15_000,
    val attempts: Int = 3,
    val circuitRace: Int = 2,
    val pickTries: Int = 8,
    val buildOnce: (suspend (TorClientDuplex, Abort, BuildOnceOptions) -> Circuit)? = null,
    val http: HttpEngine? = null,
)

data class BuildOnceOptions(
    val consensusUrls: List<String>?,
    val extendTimeoutMs: Long,
    val pickTries: Int,
    val http: HttpEngine? = null,
)

fun isTransientCircuitError(err: Any?): Boolean {
    val msg =
        when (err) {
            is Throwable -> "${err.message} ${err.cause ?: ""}"
            else -> err.toString()
        }.lowercase()
    return msg.contains("circuit destroyed") ||
        msg.contains("destroyederror") ||
        msg.contains("relay ended") ||
        msg.contains("relayendederror") ||
        msg.contains("no microdesc url succeeded") ||
        msg.contains("microdesc fetch failed") ||
        msg.contains("consensus fetch failed") ||
        msg.contains("no extendable relays") ||
        msg.contains("truncated consensus") ||
        msg.contains("timed out") ||
        msg.contains("timeouterror") ||
        Regex("http \\d{3}").containsMatchIn(msg)
}

suspend fun raceFirstCircuit(
    raceCount: Int,
    build: suspend (Abort) -> Circuit,
    signal: Abort = Abort(),
): Circuit {
    require(raceCount >= 1) { "circuitRace must be a positive integer" }
    require(raceCount.toLong().toInt() == raceCount) { "circuitRace must be a positive integer" }
    if (signal.aborted) throw signal.reason ?: CancellationException("aborted")

    val locals = Array(raceCount) { Abort() }
    val done = CompletableDeferred<Circuit>()
    val errors = ArrayList<Throwable>()
    var remaining = raceCount
    val lock = Mutex()

    supervisorScope {
        signal.onAbort {
            val reason = signal.reason ?: CancellationException("aborted")
            for (c in locals) c.abort(reason)
            done.completeExceptionally(reason)
            this.coroutineContext[Job]?.cancelChildren()
        }

        for (index in 0 until raceCount) {
            launch {
                val linked = Abort.any(signal, locals[index])
                try {
                    val circuit = build(linked)
                    if (done.isCompleted) {
                        try {
                            circuit.close()
                        } catch (_: Throwable) {
                        }
                    } else if (done.complete(circuit)) {
                        for (i in locals.indices) {
                            if (i != index) {
                                locals[i].abort(CancellationException("circuit race lost"))
                            }
                        }
                    } else {
                        try {
                            circuit.close()
                        } catch (_: Throwable) {
                        }
                    }
                } catch (err: kotlinx.coroutines.CancellationException) {
                    throw err
                } catch (err: Throwable) {
                    lock.withLock {
                        errors += err
                        remaining -= 1
                        if (!done.isCompleted && remaining == 0) {
                            done.completeExceptionally(
                                errors.firstOrNull() ?: Exception("circuit race failed"),
                            )
                        }
                    }
                }
            }
        }
        try {
            done.await()
        } catch (err: Throwable) {
            this.coroutineContext[Job]?.cancelChildren()
            throw err
        }
    }
    return done.await()
}

suspend fun buildExitCircuit(
    client: TorClientDuplex,
    signal: Abort = Abort(),
    options: BuildExitCircuitOptions = BuildExitCircuitOptions(),
): Circuit {
    val attempts = options.attempts
    val circuitRace = options.circuitRace
    require(circuitRace >= 1 && circuitRace.toDouble() == circuitRace.toInt().toDouble()) {
        "circuitRace must be a positive integer"
    }
    val once = options.buildOnce ?: { client, signal, opts -> buildExitCircuitOnce(client, signal, opts) }
    val onceOpts = BuildOnceOptions(options.consensusUrls, options.extendTimeoutMs, options.pickTries, http = options.http)
    var lastError: Throwable? = null
    var remaining = attempts
    while (remaining > 0) {
        remaining--
        if (signal.aborted) {
            throw (signal.reason as? Exception) ?: CancellationException("aborted")
        }
        try {
            return timed("tor", "circuit-race", { "race=$circuitRace" }) {
                raceFirstCircuit(circuitRace, { raceSignal ->
                    once(client, raceSignal, onceOpts)
                }, signal)
            }
        } catch (err: Throwable) {
            lastError = err
            if (signal.aborted || !isTransientCircuitError(err)) break
        }
    }
    throw lastError ?: Exception("extend circuit failed")
}

class AggregateError(
    val errors: List<Throwable>,
    message: String,
) : Exception(formatAggregate(message, errors))

private fun formatAggregate(
    message: String,
    errors: List<Throwable>,
): String {
    val details = errors.mapNotNull { it.message?.takeIf(String::isNotBlank) }.distinct()
    return if (details.isEmpty()) message else "$message: ${details.joinToString(" | ")}"
}

/**
 * Runs [worker] over [items], at most [concurrency] at a time, and returns the first result.
 * A failed worker starts the next item. As soon as one worker succeeds (or [signal] aborts, or
 * every item failed) the other workers are aborted and cancelled, and this returns right away:
 * workers run in their own scope, so a loser stuck in a blocking call is not waited for.
 */
suspend fun <T, R> fetchFirstOk(
    items: List<T>,
    worker: suspend (T, Abort) -> R,
    concurrency: Int = 4,
    signal: Abort = Abort(),
): R {
    val cap = maxOf(1, concurrency)
    require(items.isNotEmpty()) { "fetchFirstOk: empty items" }
    if (signal.aborted) throw signal.reason ?: CancellationException("aborted")

    val done = CompletableDeferred<R>()
    val errors = ArrayList<Throwable>()
    val locals = ArrayList<Abort>()
    val lock = Mutex()
    var cursor = 0
    var inFlight = 0
    val workers = CoroutineScope(currentCoroutineContext().minusKey(Job) + SupervisorJob())

    var stopped = false

    // Copies the losers under the same lock launchOne adds them with, and marks the race
    // stopped so no worker can be added after the copy. Abort is what a loser stuck in
    // non-suspending work (signature checks) observes; coroutine cancellation alone is not.
    suspend fun stopWorkers(reason: Throwable) {
        val losers =
            withContext(NonCancellable) {
                lock.withLock {
                    stopped = true
                    locals.toList()
                }
            }
        for (c in losers) {
            try {
                c.abort(reason)
            } catch (_: Throwable) {
            }
        }
        workers.cancel()
    }

    signal.onAbort {
        done.completeExceptionally(signal.reason ?: CancellationException("aborted"))
    }

    suspend fun launchOne() {
        val item: T
        val local: Abort
        lock.withLock {
            if (stopped || done.isCompleted || cursor >= items.size) return
            item = items[cursor]
            cursor += 1
            inFlight += 1
            local = Abort()
            locals += local
        }
        workers.launch {
            val linked = Abort.any(signal, local)

            suspend fun failed(err: Throwable) {
                val shouldLaunch: Boolean
                lock.withLock {
                    inFlight -= 1
                    errors += err
                    shouldLaunch = !done.isCompleted && cursor < items.size
                    if (!done.isCompleted && cursor >= items.size && inFlight == 0) {
                        done.completeExceptionally(AggregateError(errors.toList(), "fetchFirstOk: all failed"))
                    }
                }
                if (shouldLaunch) launchOne()
            }
            try {
                done.complete(worker(item, linked))
            } catch (err: kotlinx.coroutines.CancellationException) {
                // Our own cancellation (the race is over) ends quietly; any other counts as a failure.
                if (!isActive) throw err
                failed(err)
            } catch (err: Throwable) {
                failed(err)
            }
        }
    }

    try {
        repeat(minOf(cap, items.size)) { launchOne() }
        return done.await()
    } finally {
        stopWorkers(CancellationException("fetchFirstOk: lost race"))
    }
}

val AUTHORITY_HOSTS =
    listOf(
        "128.31.0.39:9231",
        "217.196.147.77:80",
        "45.66.35.11:80",
        "131.188.40.189:80",
        "193.23.244.244:80",
        "171.25.193.9:443",
        "199.58.81.140:80",
        "204.13.164.118:80",
        "216.218.219.41:80",
    )

/**
 * `.z` asks the authority for the zlib-compressed document (~0.8 MB instead of ~3.4 MB); the
 * body is inflated in [downloadVerifiedConsensus] (or already by the platform HTTP stack).
 */
val CONSENSUS_MIRRORS = AUTHORITY_HOSTS.map { "http://$it/tor/status-vote/current/consensus-microdesc.z" }

internal var cachedConsensus: Pair<Long, Consensus>? = null
internal const val CONSENSUS_CACHE_MS = 30 * 60 * 1000L

internal fun resetCachedConsensus() {
    cachedConsensus = null
    resetDiskConsensusState()
}

fun sha256Base64Unpadded(bytes: ByteArray): String = Base64.encodeUnpadded(Sha256.hash(bytes))

suspend fun fetchMicrodescConsensus(
    signal: Abort = Abort(),
    mirrors: List<String> = CONSENSUS_MIRRORS,
    force: Boolean = false,
    concurrency: Int = 3,
    engine: HttpEngine = defaultHttpEngine(),
): Consensus =
    fetchVerifiedMicrodescConsensus(
        source = ConsensusSource(mirrors, AUTHORITY_HOSTS, engine, concurrency),
        trust = ConsensusTrust(),
        force = force,
        signal = signal,
    )

suspend fun fetchMicrodesc(
    head: MicrodescHead,
    signal: Abort = Abort(),
    authorityHosts: List<String> = AUTHORITY_HOSTS,
    concurrency: Int = 4,
    engine: HttpEngine = defaultHttpEngine(),
): Microdesc {
    val dig = head.microdesc
    val urls = ArrayList<String>()
    for (host in authorityHosts) {
        urls += "http://$host/tor/micro/d/$dig.z"
        urls += "http://$host/tor/micro/d/$dig"
    }
    if (head.dirport > 0) {
        urls += "http://${head.hostname}:${head.dirport}/tor/micro/d/$dig.z"
        urls += "http://${head.hostname}:${head.dirport}/tor/micro/d/$dig"
    }
    val progress = fetchProgress()
    progress?.report(FetchStage.FETCHING_RELAY_INFO)
    try {
        return fetchFirstOk(
            urls,
            worker = { url, race ->
                race.throwIfAborted()
                val res = engine.call("GET", url, timeoutMs = 8_000, decompress = false)
                if (res.status !in 200..299 || res.body.isEmpty()) throw Exception("empty body from $url")
                val body = inflateZlibOrNull(res.body) ?: res.body
                val got = sha256Base64Unpadded(body)
                if (got != dig) throw Exception("digest mismatch for $url")
                val text = body.decodeToString()
                val parsed =
                    ConsensusParser.parseMicrodescOrThrow(text).firstOrNull()
                        ?: throw Exception("empty microdescriptor")
                Microdesc(head, parsed.onionKey, parsed.ntorOnionKey, parsed.idEd25519)
            },
            concurrency = concurrency,
            signal = signal,
        ).also { progress?.report(FetchStage.FETCHING_RELAY_INFO, 1.0) }
    } catch (err: Throwable) {
        if (signal.aborted) throw signal.reason ?: err
        throw Exception("no microdesc URL succeeded", err)
    }
}

fun createExitDialer(options: ExitDialerOptions = ExitDialerOptions()): ExitDialer {
    val hooks = options.hooks
    val engine = options.http ?: defaultHttpEngine()
    val job = kotlinx.coroutines.SupervisorJob()
    val scope = kotlinx.coroutines.CoroutineScope(job + kotlinx.coroutines.Dispatchers.Default)
    val torLock = Mutex()
    val circuitLock = Mutex()
    val circuits = LinkedHashMap<Pair<String, Int>, CachedCircuit>()
    val inflight = LinkedHashMap<Pair<String, Int>, CompletableDeferred<Circuit>>()
    val retrying = HashSet<CompletableDeferred<Circuit>>()
    var tor: TorClientDuplex? = null
    var meekStream: BatchedFetchStream? = null
    var directSocket: ByteDuplex? = null
    var ready: kotlinx.coroutines.Deferred<Unit>? = null
    var disposed = false

    fun cacheKey(
        host: String,
        port: Int,
    ) = host.lowercase() to port

    suspend fun resetTor(only: TorClientDuplex? = null) {
        val closing =
            torLock.withLock {
                if (only != null && tor !== only) return@withLock null
                val pair = tor to meekStream
                directSocket?.close()
                directSocket = null
                tor = null
                meekStream = null
                ready = null
                pair
            } ?: return
        val snapshot: List<CachedCircuit>
        val pending: List<CompletableDeferred<Circuit>>
        circuitLock.withLock {
            snapshot = circuits.values.toList()
            circuits.clear()
            val kept = inflight.filterValues { it in retrying }
            pending = inflight.values.filter { it !in retrying }
            inflight.clear()
            for ((k, deferred) in kept) inflight[k] = deferred
        }
        val reason = Exception("reset")
        for (wait in pending) {
            if (!wait.isCompleted) wait.completeExceptionally(reason)
        }
        for (cached in snapshot) {
            scope.launch {
                try {
                    cached.circuit.close()
                } catch (_: Throwable) {
                }
            }
        }
        try {
            closing.first?.close()
        } catch (_: Throwable) {
        }
        try {
            closing.second?.error(reason)
        } catch (_: Throwable) {
        }
    }

    fun wrap(
        stage: String,
        err: Throwable,
    ): Exception {
        if (err.message?.startsWith("tor ") == true && err is Exception) return err
        val causeMsg = err.cause?.message?.let { " ← $it" } ?: ""
        return Exception("tor $stage: ${err.message ?: err}$causeMsg", err)
    }

    suspend fun installClient(client: TorClientDuplex) {
        val installed =
            torLock.withLock {
                if (client.closed == null && tor == null) {
                    tor = client
                    true
                } else {
                    tor != null
                }
            }
        check(installed) { "tor connection closed" }
    }

    /** Direct ORPort bootstrap; false when the platform has no sockets. Throws on failure. */
    suspend fun bootDirect(signal: Abort): Boolean {
        val consensus = timed("tor", "direct-consensus") { fetchMicrodescConsensus(signal, engine = engine) }
        val guard = pickDirectGuard(consensus)
        val socket =
            timed("tor", "direct-connect", { "guard=${guard.nickname} addr=${guard.hostname}:${guard.orport}" }) {
                withAbortTimeout(options.directConnectTimeoutMs, signal) {
                    platformTcpConnect(guard.hostname, guard.orport, options.directConnectTimeoutMs)
                }
            } ?: return false
        val client = TorClientDuplex(Base64.decode(guard.identity))
        directSocket = socket
        try {
            scope.launch {
                pipeDuplex(socket, client.inner)
                if (tor === client) resetTor(client)
            }
            scope.launch {
                pipeDuplex(client.inner, socket)
                if (tor === client) resetTor(client)
            }
            timed("tor", "direct-handshake") {
                withAbortTimeout(options.directHandshakeTimeoutMs, signal) { client.waitOrThrow(it) }
            }
            installClient(client)
            lastDirectGuard = "${guard.nickname} ${guard.hostname}:${guard.orport}"
            return true
        } catch (err: Throwable) {
            socket.close()
            try {
                client.close()
            } catch (_: Throwable) {
            }
            if (directSocket === socket) directSocket = null
            // Pick another guard next time rather than retrying a dead one forever.
            forgetDirectGuard()
            throw err
        }
    }

    fun beginBootstrap(
        signal: Abort,
        progress: FetchProgressReporter?,
    ) = scope.async {
        progress?.report(FetchStage.CONNECTING)
        if (options.directGuard && hooks.makeCircuit == null) {
            val direct =
                try {
                    bootDirect(signal)
                } catch (err: CancellationException) {
                    throw err
                } catch (err: Throwable) {
                    if (signal.aborted) throw wrap("bootstrap", err)
                    println("echalote.direct failed, falling back to meek: ${err.message}")
                    false
                }
            if (direct) {
                lastBootstrapRoute = TorRoute.DIRECT
                progress?.report(FetchStage.CONNECTING, 1.0)
                return@async
            }
        }
        if (options.prefetchConsensus && hooks.makeCircuit == null) {
            scope.launch {
                try {
                    timed("tor", "consensus-prefetch") { fetchMicrodescConsensus(engine = engine) }
                } catch (err: Throwable) {
                    println("echalote.consensus prefetch failed: ${err.message}")
                }
            }
        }
        val meek = createMeekStream(options.meekUrl, engine)
        val client = TorClientDuplex()
        meekStream = meek
        try {
            scope.launch {
                try {
                    pipeDuplex(meek.duplex, client.inner)
                } catch (_: Throwable) {
                }
                if (tor === client) resetTor(client)
            }
            scope.launch {
                try {
                    pipeDuplex(client.inner, meek.duplex)
                } catch (_: Throwable) {
                }
                if (tor === client) resetTor(client)
            }
            timed("tor", "meek-start") { meek.start() }
            timed("tor", "tor-handshake") { client.waitOrThrow(signal) }
            progress?.report(FetchStage.CONNECTING, 1.0)
            installClient(client)
            lastBootstrapRoute = TorRoute.MEEK
        } catch (err: Throwable) {
            try {
                meek.error(err)
            } catch (_: Throwable) {
            }
            try {
                client.close()
            } catch (_: Throwable) {
            }
            val attempt = kotlin.coroutines.coroutineContext[kotlinx.coroutines.Job]
            torLock.withLock {
                if (meekStream === meek) meekStream = null
                if (ready === attempt) ready = null
            }
            throw wrap("bootstrap", err)
        }
    }

    suspend fun awaitBoot(
        signal: Abort,
        progress: FetchProgressReporter?,
    ): TorClientDuplex? {
        val boot: Boot =
            torLock.withLock {
                if (disposed) throw Exception("exit dialer disposed")
                if (tor?.closed != null) {
                    Boot.Retry
                } else if (tor != null) {
                    Boot.Ready
                } else {
                    if (ready == null) ready = beginBootstrap(signal, progress)
                    Boot.Wait(ready!!)
                }
            }
        val client =
            when (boot) {
                Boot.Retry -> null
                Boot.Ready -> tor ?: error("tor client failed to start")
                is Boot.Wait -> {
                    runCatching { withAbort(signal) { boot.deferred.await() } }.getOrElse { err ->
                        throw wrap("bootstrap", err)
                    }
                    progress?.report(FetchStage.CONNECTING, 1.0)
                    tor ?: error("tor client failed to start")
                }
            }
        return client
    }

    suspend fun bootClient(
        signal: Abort,
        progress: FetchProgressReporter?,
    ): TorClientDuplex? {
        val stale = torLock.withLock { tor?.takeIf { it.closed != null } }
        val booted =
            if (stale != null) {
                resetTor(stale)
                null
            } else {
                awaitBoot(signal, progress)
            }
        return booted
    }

    suspend fun ensureTor(signal: Abort): TorClientDuplex {
        if (disposed) throw Exception("exit dialer disposed")
        signal.throwIfAborted()
        val progress = fetchProgress()
        progress?.report(FetchStage.CONNECTING)
        val hook = hooks.ensureTor
        val hooked =
            if (hook == null) {
                null
            } else {
                if (tor?.closed != null) tor = null
                tor ?: hook(signal).also { tor = it }
            }
        if (hooked != null) {
            progress?.report(FetchStage.CONNECTING, 1.0)
            return hooked
        }
        var client: TorClientDuplex? = null
        var failures = 0
        while (client == null) {
            client =
                try {
                    bootClient(signal, progress)
                } catch (err: Throwable) {
                    // A meek front answers 502 now and then (seen in ~1 of 20 live runs); one
                    // fresh session usually works, so retry the bootstrap once.
                    if (err is CancellationException || signal.aborted || ++failures > 1) throw err
                    println("echalote.bootstrap retry after: ${err.message}")
                    null
                }
        }
        return client
    }

    suspend fun makeExitCircuit(
        client: TorClientDuplex,
        signal: Abort,
    ): Circuit {
        if (hooks.makeCircuit != null) return hooks.makeCircuit.invoke(client, signal)
        try {
            return buildExitCircuit(
                client,
                signal,
                BuildExitCircuitOptions(
                    extendTimeoutMs = options.extendTimeoutMs,
                    attempts = options.circuitAttempts,
                    circuitRace = options.circuitRace,
                    http = engine,
                ),
            )
        } catch (err: Throwable) {
            throw if (err is Exception && err.message?.startsWith("tor ") == true) err else wrap("extend circuit", err)
        }
    }

    suspend fun evictCircuit(key: Pair<String, Int>) {
        val cached = circuits.remove(key) ?: return
        try {
            cached.circuit.close()
        } catch (_: Throwable) {
        }
    }

    fun fresh(cached: CachedCircuit): Boolean {
        val stale =
            options.maxCircuitAgeMs > 0L &&
                hooks.nowMs() - cached.createdAtMs >= options.maxCircuitAgeMs
        return !stale && !cached.circuit.isClosed
    }

    fun rethrowCircuit(err: Throwable): Nothing {
        if (err is Exception && err.message?.startsWith("tor ") == true) throw err
        throw wrap("extend circuit", err)
    }

    suspend fun buildWithOneRetry(
        client: TorClientDuplex,
        signal: Abort,
    ): Circuit =
        try {
            makeExitCircuit(client, signal)
        } catch (err: Throwable) {
            if (hooks.makeCircuit != null || !isTransientCircuitError(err) || signal.aborted) {
                rethrowCircuit(err)
            }
            resetTor(client)
            makeExitCircuit(ensureTor(signal), signal)
        }

    suspend fun leadCircuit(
        client: TorClientDuplex,
        signal: Abort,
        key: Pair<String, Int>,
        flight: Flight.Lead,
    ): Circuit {
        circuitLock.withLock { retrying += flight.deferred }
        try {
            val built = buildWithOneRetry(client, signal)
            val installed =
                circuitLock.withLock {
                    if (inflight[key] !== flight.deferred) {
                        false
                    } else {
                        inflight.remove(key)
                        circuits[key] = CachedCircuit(built, hooks.nowMs())
                        true
                    }
                }
            if (!installed) {
                scope.launch { runCatching { built.close() } }
                error("circuit build was reset")
            }
            flight.deferred.complete(built)
            return built
        } catch (err: Throwable) {
            circuitLock.withLock {
                if (inflight[key] === flight.deferred) inflight.remove(key)
            }
            flight.deferred.completeExceptionally(err)
            throw err
        } finally {
            circuitLock.withLock { retrying -= flight.deferred }
        }
    }

    suspend fun obtainCircuit(
        client: TorClientDuplex,
        signal: Abort,
        key: Pair<String, Int>,
    ): Circuit {
        val flight: Flight =
            circuitLock.withLock {
                if (disposed) throw Exception("exit dialer disposed")

                fun joinOrLead(): Flight {
                    val pending = inflight[key]
                    if (pending != null) return Flight.Join(pending)
                    val created = CompletableDeferred<Circuit>()
                    inflight[key] = created
                    return Flight.Lead(created)
                }
                val cached = circuits[key]
                val chosen: Flight =
                    if (cached != null && fresh(cached)) {
                        Flight.Hit(cached.circuit)
                    } else {
                        if (cached != null) {
                            circuits.remove(key)
                            scope.launch { runCatching { cached.circuit.close() } }
                        }
                        joinOrLead()
                    }
                chosen
            }
        return when (flight) {
            is Flight.Hit -> flight.circuit
            is Flight.Join -> withAbort(signal) { flight.deferred.await() }
            is Flight.Lead -> leadCircuit(client, signal, key, flight)
        }
    }

    return object : ExitDialer {
        override suspend fun dial(
            host: String,
            port: Int,
            abort: Abort?,
            onProgress: FetchProgressListener?,
        ): TorStreamDuplex = openStream(host, port, abort, onProgress, wait = true)

        override suspend fun dialOptimistic(
            host: String,
            port: Int,
            abort: Abort?,
        ): TorStreamDuplex = openStream(host, port, abort, null, wait = false)

        suspend fun openStream(
            host: String,
            port: Int,
            abort: Abort?,
            onProgress: FetchProgressListener?,
            wait: Boolean,
        ): TorStreamDuplex {
            suspend fun open(): TorStreamDuplex {
                if (disposed) throw Exception("exit dialer disposed")
                val signal = abort ?: Abort()
                val key = cacheKey(host, port)
                var retried = false
                while (true) {
                    val client = timed("tor", "ensure-tor") { ensureTor(signal) }
                    val cached = circuitLock.withLock { circuits[key] }
                    val cacheHit = cached != null && !cached.circuit.isClosed
                    val circuit = timed("tor", "obtain-circuit", { "cacheHit=$cacheHit" }) { obtainCircuit(client, signal, key) }
                    val progress = fetchProgress()
                    progress?.report(FetchStage.OPENING_CONNECTION)
                    println(
                        "echalote.dial $host:$port retry=$retried cacheHit=$cacheHit circ=${circuit.id} " +
                            "torClosed=${client.closed != null}",
                    )
                    try {
                        val stream =
                            timed("tor", "stream-open", { "circ=${circuit.id} wait=$wait" }) {
                                withAbortTimeout(options.openTimeoutMs, signal) { linked ->
                                    circuit.openOrThrow(host, port, wait = wait, abort = linked)
                                }
                            }
                        progress?.report(FetchStage.OPENING_CONNECTION, 0.5)
                        println("echalote.open-ok $host:$port circ=${circuit.id}")
                        return TorStreamDuplex(stream.outer) { stream.close() }
                    } catch (err: Throwable) {
                        println("echalote.open-fail $host:$port circ=${circuit.id} ${err.message}")
                        circuitLock.withLock { evictCircuit(key) }
                        if (retried || signal.aborted) throw wrap("open $host:$port", err)
                        retried = true
                    }
                }
            }
            if (onProgress == null) return open()
            val reporter = FetchProgressReporter(onProgress)
            return withContext(FetchProgressContext(reporter)) {
                reporter.report(FetchStage.STARTING)
                val stream = open()
                reporter.report(FetchStage.DONE)
                stream
            }
        }

        override suspend fun forgetCircuit(
            host: String,
            port: Int,
        ) {
            circuitLock.withLock { evictCircuit(cacheKey(host, port)) }
        }

        override suspend fun dispose() {
            disposed = true
            resetTor()
            job.cancel()
        }
    }
}

internal const val DIRECT_GUARD_KEY = "direct-guard"

internal fun isDirectGuardCandidate(head: MicrodescHead): Boolean {
    val f = head.flags
    return "Guard" in f &&
        "Fast" in f &&
        "Stable" in f &&
        "Running" in f &&
        "Valid" in f &&
        "Exit" !in f &&
        head.orport > 0
}

/**
 * The guard for direct mode: the one saved earlier if the consensus still lists it as a
 * guard, else a bandwidth-weighted pick that is then saved, so one device keeps using the
 * same entry relay (as Tor itself does) instead of meeting a new one every launch.
 */
internal suspend fun pickDirectGuard(consensus: Consensus): MicrodescHead {
    val pool = consensus.microdescs.filter(::isDirectGuardCandidate)
    if (pool.isEmpty()) throw Exception("tor consensus has no usable guards")
    val saved = runCatching { torDirCache.read(DIRECT_GUARD_KEY)?.decodeToString() }.getOrNull()
    pool.firstOrNull { it.identity == saved }?.let { return it }
    val weights = pool.map { (it.bandwidth["Bandwidth"]?.toLongOrNull() ?: 0L).coerceAtLeast(1L) }
    val total = weights.sum()
    var r = (randomIndex(Int.MAX_VALUE).toLong() * total) / Int.MAX_VALUE
    var pick = pool.last()
    for ((i, w) in weights.withIndex()) {
        if (r < w) {
            pick = pool[i]
            break
        }
        r -= w
    }
    runCatching { torDirCache.write(DIRECT_GUARD_KEY, pick.identity.encodeToByteArray()) }
    return pick
}

internal suspend fun forgetDirectGuard() {
    runCatching { torDirCache.delete(DIRECT_GUARD_KEY) }
}

internal suspend fun pickExtendable(
    pool: List<MicrodescHead>,
    signal: Abort,
    tries: Int,
    engine: HttpEngine,
): Microdesc {
    val remaining = pool.toMutableList()
    var last: Throwable = Exception("no extendable relays")
    var i = 0
    while (i < tries && remaining.isNotEmpty()) {
        val idx = randomIndex(remaining.size)
        val head = remaining.removeAt(idx)
        try {
            return fetchMicrodesc(head, signal, engine = engine)
        } catch (err: Throwable) {
            last = err
        }
        i++
    }
    throw last
}

private fun usableRelay(
    head: MicrodescHead,
    guardId: ByteArray?,
    exit: Boolean,
): Boolean {
    val flags = head.flags
    val role = if (exit) flags.contains("Exit") && !flags.contains("BadExit") else flags.contains("V2Dir")
    val notGuard = guardId == null || !equalBytes(Base64.decode(head.identity), guardId)
    return role && flags.contains("Fast") && flags.contains("Stable") && notGuard
}

internal suspend fun buildExitCircuitOnce(
    client: TorClientDuplex,
    signal: Abort,
    options: BuildOnceOptions,
): Circuit {
    val progress = fetchProgress()
    val engine = options.http ?: defaultHttpEngine()
    val buildStart = timeMark()
    val circuit = timed("tor", "create-fast") { withAbortTimeout(options.extendTimeoutMs, signal) { client.createOrThrow(it) } }
    val tag = { "circ=${circuit.id}" }
    try {
        val consensus =
            timed("tor", "consensus", tag) {
                fetchMicrodescConsensus(
                    signal,
                    mirrors = options.consensusUrls ?: CONSENSUS_MIRRORS,
                    engine = engine,
                )
            }
        val guardId =
            (circuit as? LiveCircuit)
                ?.secret
                ?.targets
                ?.firstOrNull()
                ?.relayidRsa
        val middles = consensus.microdescs.filter { usableRelay(it, guardId, exit = false) }
        val exits = consensus.microdescs.filter { usableRelay(it, guardId, exit = true) }
        if (middles.isEmpty() || exits.isEmpty()) {
            throw Exception("tor consensus missing usable relays (middles=${middles.size} exits=${exits.size})")
        }
        val middleFull = timed("tor", "microdesc-middle", tag) { pickExtendable(middles, signal, options.pickTries, engine) }
        progress?.report(FetchStage.BUILDING_CIRCUIT)
        timed("tor", "extend2-middle", tag) { withAbortTimeout(options.extendTimeoutMs, signal) { circuit.extendOrThrow(middleFull, it) } }
        progress?.report(FetchStage.BUILDING_CIRCUIT, 0.5)
        val exitFull =
            timed("tor", "microdesc-exit", tag) {
                pickExtendable(
                    exits.filter { it.identity != middleFull.identity },
                    signal,
                    options.pickTries,
                    engine,
                )
            }
        timed("tor", "extend2-exit", tag) { withAbortTimeout(options.extendTimeoutMs, signal) { circuit.extendOrThrow(exitFull, it) } }
        progress?.report(FetchStage.BUILDING_CIRCUIT, 1.0)
        logTiming("tor", "circuit-build", buildStart.elapsedNow(), tag())
        return circuit
    } catch (err: Throwable) {
        try {
            circuit.close()
        } catch (_: Throwable) {
        }
        throw err
    }
}

object Echalote {
    const val DEFAULT_MEEK_URL = io.bluewallet.echalote.DEFAULT_MEEK_URL

    /**
     * Persistent cache for the consensus and authority certificates, shared by every client in
     * this process. Defaults to [TorDirCache.None]. Set it once at startup, before the first
     * fetch; cached documents are always re-verified before use.
     */
    var dirCache: TorDirCache
        get() = torDirCache
        set(value) {
            torDirCache = value
        }

    /**
     * Prints one timestamped `echalote.*.trace` line per meek POST, Tor cell and TLS flight.
     * Off by default; meant for diagnosing where a slow start spends its time.
     */
    var verboseTrace: Boolean
        get() = io.bluewallet.echalote.verboseTrace
        set(value) {
            io.bluewallet.echalote.verboseTrace = value
        }

    /**
     * Opt-in direct relay mode for the default client ([ExitDialerOptions.directGuard]):
     * connects straight to a guard relay, falling back to meek. Setting this only affects
     * connections opened afterwards; an already-open Tor connection and its kept-alive HTTPS
     * sessions keep their route. To switch at runtime use [setDirectRelay], which applies the
     * change to the very next request in both directions.
     */
    var directRelay: Boolean
        get() = directRelayEnabled
        set(value) {
            directRelayEnabled = value
        }

    /**
     * Turns direct relay mode on or off and applies it immediately: if the mode in use changes,
     * the current Tor connection and kept-alive HTTPS sessions are closed, so the next request
     * reconnects the new way (in-flight requests are retried on a fresh connection). Calling it
     * with the current mode does nothing.
     */
    suspend fun setDirectRelay(enabled: Boolean) = setDefaultDirectRelay(enabled)

    /**
     * Closes the default client's Tor connection, circuits and kept-alive HTTPS sessions. The
     * next request bootstraps again with the current settings. Requests in flight fail and are
     * retried once by [fetch] on the fresh connection.
     */
    suspend fun resetConnections() = resetDefaultExitDialer()

    /** Prints a `echalote.mark.trace` line with [label], to delimit runs in a trace. */
    fun traceMark(label: String) = println("echalote.mark.trace t=${traceNow()} ev=$label")

    fun createExitDialer(options: ExitDialerOptions = ExitDialerOptions()) = io.bluewallet.echalote.createExitDialer(options)

    suspend fun dial(
        host: String,
        port: Int,
        abort: Abort? = null,
        onProgress: FetchProgressListener? = null,
    ) = defaultExitDialer().dial(host, port, abort, onProgress)

    fun createMeekStream(url: String = io.bluewallet.echalote.DEFAULT_MEEK_URL) = io.bluewallet.echalote.createMeekStream(url)

    fun initBundledCrypto() = io.bluewallet.echalote.initBundledCrypto()

    suspend fun fetchMicrodescConsensus(signal: Abort = Abort()) = io.bluewallet.echalote.fetchMicrodescConsensus(signal)

    suspend fun fetchMicrodesc(
        head: MicrodescHead,
        signal: Abort = Abort(),
    ) = io.bluewallet.echalote.fetchMicrodesc(head, signal)

    suspend fun buildExitCircuit(
        client: TorClientDuplex,
        signal: Abort = Abort(),
        options: BuildExitCircuitOptions = BuildExitCircuitOptions(),
    ) = io.bluewallet.echalote.buildExitCircuit(client, signal, options)

    suspend fun streamFetch(
        url: String,
        init: StreamFetchInit,
    ) = io.bluewallet.echalote.streamFetch(url, init)

    suspend fun fetch(
        url: String,
        abort: Abort? = null,
        method: String = "GET",
        headers: Map<String, String> = emptyMap(),
        body: ByteArray = ByteArray(0),
        onProgress: FetchProgressListener? = null,
    ) = io.bluewallet.echalote.httpsFetch(url, abort, method, headers, body, onProgress)

    /** See [io.bluewallet.echalote.warmUpHttps]: pre-opens Tor, the exit circuit and TLS for [url]. */
    suspend fun warmUp(
        url: String,
        abort: Abort? = null,
    ) = io.bluewallet.echalote.warmUpHttps(url, abort)

    suspend fun wrapTls(
        transport: ByteDuplex,
        hostName: String,
        abort: Abort? = null,
    ) = io.bluewallet.echalote.wrapTls(transport, hostName, abort)
}
