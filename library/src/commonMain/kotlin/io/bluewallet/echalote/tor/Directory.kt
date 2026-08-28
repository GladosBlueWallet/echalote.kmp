package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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

    init {
        duplex.onWrite = { bytes ->
            mutex.withLock { chunks += bytes.copyOf() }
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

    private suspend fun takeBody(): ByteArray = mutex.withLock {
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
                val res = engine.call(
                    "POST",
                    url,
                    headers = mapOf("x-session-id" to sessionId),
                    body = body,
                    timeoutMs = 30_000,
                )
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
)

interface ExitDialer {
    suspend fun dial(host: String, port: Int, abort: Abort? = null): TorStreamDuplex
    suspend fun dispose()
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
    val msg = when (err) {
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
    if (raceCount < 1) throw IllegalArgumentException("circuitRace must be a positive integer")
    if (raceCount.toLong().toInt() != raceCount) throw IllegalArgumentException("circuitRace must be a positive integer")
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
                        for (i in locals.indices) if (i != index) {
                            locals[i].abort(CancellationException("circuit race lost"))
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
    if (circuitRace < 1 || circuitRace.toDouble() != circuitRace.toInt().toDouble()) {
        throw IllegalArgumentException("circuitRace must be a positive integer")
    }
    val once = options.buildOnce ?: { client, signal, opts -> buildExitCircuitOnce(client, signal, opts) }
    val onceOpts = BuildOnceOptions(options.consensusUrls, options.extendTimeoutMs, options.pickTries, http = options.http)
    var lastError: Throwable? = null
    for (attempt in 1..attempts) {
        if (signal.aborted) {
            throw (signal.reason as? Exception) ?: CancellationException("aborted")
        }
        try {
            return raceFirstCircuit(circuitRace, { raceSignal ->
                once(client, raceSignal, onceOpts)
            }, signal)
        } catch (err: Throwable) {
            lastError = err
            if (signal.aborted || !isTransientCircuitError(err)) break
        }
    }
    throw lastError ?: Exception("extend circuit failed")
}

class AggregateError(val errors: List<Throwable>, message: String) : Exception(formatAggregate(message, errors))

private fun formatAggregate(message: String, errors: List<Throwable>): String {
    val details = errors.mapNotNull { it.message?.takeIf(String::isNotBlank) }.distinct()
    return if (details.isEmpty()) message else "$message: ${details.joinToString(" | ")}"
}

suspend fun <T, R> fetchFirstOk(
    items: List<T>,
    worker: suspend (T, Abort) -> R,
    concurrency: Int = 4,
    signal: Abort = Abort(),
): R {
    val cap = maxOf(1, concurrency)
    if (items.isEmpty()) throw IllegalArgumentException("fetchFirstOk: empty items")
    if (signal.aborted) throw signal.reason ?: CancellationException("aborted")

    val done = CompletableDeferred<R>()
    val errors = ArrayList<Throwable>()
    val locals = ArrayList<Abort>()
    val lock = Mutex()
    var cursor = 0
    var inFlight = 0

    fun settleReject(err: Throwable) {
        if (done.isCompleted) return
        done.completeExceptionally(err)
        for (c in locals) c.abort(err)
    }

    fun settleResolve(value: R) {
        if (done.isCompleted) return
        done.complete(value)
        for (c in locals) {
            try {
                c.abort(CancellationException("fetchFirstOk: lost race"))
            } catch (_: Throwable) {
            }
        }
    }

    signal.onAbort {
        settleReject(signal.reason ?: CancellationException("aborted"))
    }

    coroutineScope {
        suspend fun launchOne() {
            val item: T
            val local: Abort
            lock.withLock {
                if (done.isCompleted || cursor >= items.size) return
                item = items[cursor]
                cursor += 1
                inFlight += 1
                local = Abort()
                locals += local
            }
            launch {
                val linked = Abort.any(signal, local)
                try {
                    val value = worker(item, linked)
                    settleResolve(value)
                } catch (err: kotlinx.coroutines.CancellationException) {
                    throw err
                } catch (err: Throwable) {
                    val shouldLaunch: Boolean
                    lock.withLock {
                        inFlight -= 1
                        errors += err
                        shouldLaunch = !done.isCompleted && cursor < items.size
                        if (!done.isCompleted && cursor >= items.size && inFlight == 0) {
                            settleReject(AggregateError(errors.toList(), "fetchFirstOk: all failed"))
                        }
                    }
                    if (shouldLaunch) launchOne()
                }
            }
        }
        repeat(minOf(cap, items.size)) { launchOne() }
        try {
            done.await()
        } finally {
            this.coroutineContext[Job]?.cancelChildren()
        }
    }
    return done.await()
}

val AUTHORITY_HOSTS = listOf(
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

val CONSENSUS_MIRRORS = AUTHORITY_HOSTS.map { "http://$it/tor/status-vote/current/consensus-microdesc" }

private var cachedConsensus: Pair<Long, Consensus>? = null
private const val CACHE_MS = 30 * 60 * 1000L

fun sha256Base64Unpadded(bytes: ByteArray): String =
    Base64.encodeUnpadded(Sha256.hash(bytes))

suspend fun fetchMicrodescConsensus(
    signal: Abort = Abort(),
    mirrors: List<String> = CONSENSUS_MIRRORS,
    force: Boolean = false,
    concurrency: Int = 3,
    engine: HttpEngine = defaultHttpEngine(),
): Consensus {
    val cached = cachedConsensus
    if (!force && cached != null && currentEpochMillis() - cached.first < CACHE_MS) {
        return cached.second
    }
    val shuffled = mirrors.toMutableList().also { it.shuffle() }
    val consensus = fetchFirstOk(
        shuffled,
        worker = { url, race ->
            race.throwIfAborted()
            val res = engine.call("GET", url, timeoutMs = 30_000)
            if (res.status !in 200..299) throw Exception("HTTP ${res.status}")
            val text = res.body.decodeToString()
            if (!text.contains("directory-footer")) throw Exception("truncated consensus (no directory-footer)")
            val parsed = ConsensusParser.parseOrThrow(text)
            if (parsed.microdescs.isEmpty()) throw Exception("consensus has no microdescs")
            parsed
        },
        concurrency = concurrency,
        signal = signal,
    )
    cachedConsensus = currentEpochMillis() to consensus
    return consensus
}

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
                val parsed = ConsensusParser.parseMicrodescOrThrow(text).firstOrNull()
                    ?: throw Exception("empty microdescriptor")
                Microdesc(head, parsed.onionKey, parsed.ntorOnionKey, parsed.idEd25519)
            },
            concurrency = concurrency,
            signal = signal,
        )
    } catch (err: Throwable) {
        if (signal.aborted) throw signal.reason ?: err
        throw Exception("no microdesc URL succeeded", err)
    }
}

fun createExitDialer(options: ExitDialerOptions = ExitDialerOptions()): ExitDialer {
    val engine = options.http ?: defaultHttpEngine()
    val job = kotlinx.coroutines.SupervisorJob()
    val scope = kotlinx.coroutines.CoroutineScope(job + kotlinx.coroutines.Dispatchers.Default)
    val torLock = Mutex()
    var tor: TorClientDuplex? = null
    var meekStream: BatchedFetchStream? = null
    var ready: kotlinx.coroutines.Deferred<Unit>? = null
    var disposed = false

    fun resetTor() {
        try {
            tor?.close()
        } catch (_: Throwable) {
        }
        try {
            meekStream?.error(Exception("reset"))
        } catch (_: Throwable) {
        }
        tor = null
        meekStream = null
        ready = null
    }

    fun wrap(stage: String, err: Throwable): Exception {
        if (err.message?.startsWith("tor ") == true && err is Exception) return err
        val causeMsg = err.cause?.message?.let { " ← $it" } ?: ""
        return Exception("tor $stage: ${err.message ?: err}$causeMsg", err)
    }

    suspend fun ensureTor(signal: Abort): TorClientDuplex {
        if (disposed) throw Exception("exit dialer disposed")
        signal.throwIfAborted()
        val boot = torLock.withLock {
            if (disposed) throw Exception("exit dialer disposed")
            if (tor?.closed != null) resetTor()
            tor?.let { return it }
            if (ready == null) {
                ready = scope.async {
                    val meek = createMeekStream(options.meekUrl, engine)
                    val client = TorClientDuplex()
                    meekStream = meek
                    try {
                        scope.launch {
                            try {
                                pipeDuplex(meek.duplex, client.inner)
                            } catch (_: Throwable) {
                            }
                            if (tor === client) resetTor()
                        }
                        scope.launch {
                            try {
                                pipeDuplex(client.inner, meek.duplex)
                            } catch (_: Throwable) {
                            }
                            if (tor === client) resetTor()
                        }
                        meek.start()
                        client.waitOrThrow(signal)
                        tor = client
                    } catch (err: Throwable) {
                        try {
                            meek.error(err)
                        } catch (_: Throwable) {
                        }
                        try {
                            client.close()
                        } catch (_: Throwable) {
                        }
                        meekStream = null
                        ready = null
                        throw wrap("bootstrap", err)
                    }
                }
            }
            ready!!
        }
        try {
            withAbort(signal) { boot.await() }
        } catch (err: Throwable) {
            throw if (err is Exception && err.message?.startsWith("tor ") == true) err else wrap("bootstrap", err)
        }
        return tor ?: throw Exception("tor client failed to start")
    }

    suspend fun makeExitCircuit(client: TorClientDuplex, signal: Abort): Circuit {
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

    return object : ExitDialer {
        override suspend fun dial(host: String, port: Int, abort: Abort?): TorStreamDuplex {
            if (disposed) throw Exception("exit dialer disposed")
            val signal = abort ?: Abort()
            var client = ensureTor(signal)
            var circuit: Circuit
            try {
                circuit = makeExitCircuit(client, signal)
            } catch (err: Throwable) {
                if (isTransientCircuitError(err) && !signal.aborted) {
                    resetTor()
                    client = ensureTor(signal)
                    circuit = makeExitCircuit(client, signal)
                } else {
                    throw if (err is Exception && err.message?.startsWith("tor ") == true) err else wrap("extend circuit", err)
                }
            }
            try {
                val stream = withAbortTimeout(options.openTimeoutMs, signal) { linked ->
                    circuit.openOrThrow(host, port, wait = true, abort = linked)
                }
                return TorStreamDuplex(stream.outer) {
                    stream.close()
                    scope.launch {
                        try {
                            circuit.close()
                        } catch (_: Throwable) {
                        }
                    }
                }
            } catch (err: Throwable) {
                try {
                    circuit.close()
                } catch (_: Throwable) {
                }
                throw wrap("open $host:$port", err)
            }
        }

        override suspend fun dispose() {
            disposed = true
            resetTor()
            job.cancel()
        }
    }
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
        val idx = (secureRandom(1)[0].toInt() and 0xff) % remaining.size
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

internal suspend fun buildExitCircuitOnce(
    client: TorClientDuplex,
    signal: Abort,
    options: BuildOnceOptions,
): Circuit {
    val engine = options.http ?: defaultHttpEngine()
    val circuit = client.createOrThrow(signal)
    try {
        val consensus = fetchMicrodescConsensus(
            signal,
            mirrors = options.consensusUrls ?: CONSENSUS_MIRRORS,
            engine = engine,
        )
        val middles = consensus.microdescs.filter {
            it.flags.contains("Fast") && it.flags.contains("Stable") && it.flags.contains("V2Dir")
        }
        val exits = consensus.microdescs.filter {
            it.flags.contains("Fast") && it.flags.contains("Stable") &&
                it.flags.contains("Exit") && !it.flags.contains("BadExit")
        }
        if (middles.isEmpty() || exits.isEmpty()) {
            throw Exception("tor consensus missing usable relays (middles=${middles.size} exits=${exits.size})")
        }
        val middleFull = pickExtendable(middles, signal, options.pickTries, engine)
        withAbortTimeout(options.extendTimeoutMs, signal) { circuit.extendOrThrow(middleFull, it) }
        val exitFull = pickExtendable(
            exits.filter { it.identity != middleFull.identity },
            signal,
            options.pickTries,
            engine,
        )
        withAbortTimeout(options.extendTimeoutMs, signal) { circuit.extendOrThrow(exitFull, it) }
        return circuit
    } catch (err: Throwable) {
        try {
            circuit.close()
        } catch (_: Throwable) {
        }
        throw err
    }
}

private fun <T> MutableList<T>.shuffle() {
    for (i in size - 1 downTo 1) {
        val j = (secureRandom(1)[0].toInt() and 0xff) % (i + 1)
        val t = this[i]
        this[i] = this[j]
        this[j] = t
    }
}

object Echalote {
    const val DEFAULT_MEEK_URL = io.bluewallet.echalote.DEFAULT_MEEK_URL
    fun createExitDialer(options: ExitDialerOptions = ExitDialerOptions()) =
        io.bluewallet.echalote.createExitDialer(options)
    fun createMeekStream(url: String = io.bluewallet.echalote.DEFAULT_MEEK_URL) =
        io.bluewallet.echalote.createMeekStream(url)
    fun initBundledCrypto() = io.bluewallet.echalote.initBundledCrypto()
    suspend fun fetchMicrodescConsensus(signal: Abort = Abort()) =
        io.bluewallet.echalote.fetchMicrodescConsensus(signal)
    suspend fun fetchMicrodesc(head: MicrodescHead, signal: Abort = Abort()) =
        io.bluewallet.echalote.fetchMicrodesc(head, signal)
    suspend fun buildExitCircuit(
        client: TorClientDuplex,
        signal: Abort = Abort(),
        options: BuildExitCircuitOptions = BuildExitCircuitOptions(),
    ) = io.bluewallet.echalote.buildExitCircuit(client, signal, options)
    suspend fun streamFetch(url: String, init: StreamFetchInit) =
        io.bluewallet.echalote.streamFetch(url, init)
    suspend fun wrapTls(transport: ByteDuplex, hostName: String, abort: Abort? = null) =
        io.bluewallet.echalote.wrapTls(transport, hostName, abort)
}
