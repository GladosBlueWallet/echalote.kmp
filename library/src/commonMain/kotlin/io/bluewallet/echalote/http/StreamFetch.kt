package io.bluewallet.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.CancellationException as CoroutineCancellation

internal const val TOR_BROWSER_USER_AGENT =
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"

data class StreamFetchInit(
    val stream: ByteDuplex,
    val abort: Abort? = null,
    val headers: Map<String, String> = emptyMap(),
    val method: String = "GET",
    val body: ByteArray = ByteArray(0),
)

data class StreamResponse(
    val status: Int,
    val statusText: String,
    val headers: Map<String, String>,
    val body: ByteArray,
) {
    val ok: Boolean get() = status in 200..299

    fun text(): String = body.decodeToString()

    fun jsonObject(): Map<String, String> {
        val t = text().trim()
        require(t.startsWith("{") && t.endsWith("}")) { "not a json object" }
        val inner = t.substring(1, t.length - 1).trim()
        if (inner.isEmpty()) return emptyMap()
        val out = mutableMapOf<String, String>()
        // tiny parser for {"IsTor":true,"IP":"..."}
        var i = 0

        fun skipWs() {
            while (i < inner.length && inner[i].isWhitespace()) i++
        }
        while (i < inner.length) {
            skipWs()
            require(inner[i] == '"') { "expected key" }
            i++
            val ks = i
            while (inner[i] != '"') i++
            val key = inner.substring(ks, i)
            i++
            skipWs()
            require(inner[i] == ':')
            i++
            skipWs()
            val value: String
            if (inner[i] == '"') {
                i++
                val vs = i
                while (inner[i] != '"') i++
                value = inner.substring(vs, i)
                i++
            } else {
                val vs = i
                while (i < inner.length && inner[i] != ',' && inner[i] != '}') i++
                value = inner.substring(vs, i).trim()
            }
            out[key] = value
            skipWs()
            if (i < inner.length && inner[i] == ',') i++
        }
        return out
    }
}

suspend fun streamFetch(
    input: String,
    init: StreamFetchInit,
): StreamResponse {
    val abort = init.abort
    abort?.throwIfAborted()
    val url = parseUrl(input)
    val headers = LinkedHashMap<String, String>()
    if (init.headers.keys.none { it.equals("Host", true) }) headers["Host"] = url.host
    if (init.headers.keys.none { it.equals("Connection", true) }) headers["Connection"] = "keep-alive"
    if (init.headers.keys.none { it.equals("User-Agent", true) }) {
        headers["User-Agent"] = TOR_BROWSER_USER_AGENT
    }
    headers.putAll(init.headers)
    val method = init.method.ifBlank { "GET" }
    val hasLength = headers.keys.any { it.equals("Content-Length", true) }
    val needsLength = init.body.isNotEmpty() || method.uppercase() in setOf("POST", "PUT", "PATCH")
    if (!hasLength && needsLength) {
        headers["Content-Length"] = init.body.size.toString()
    }
    val head =
        buildString {
            append("$method ${url.target} HTTP/1.1\r\n")
            for ((k, v) in headers) append("$k: $v\r\n")
            append("\r\n")
        }
    val progress = fetchProgress()
    init.stream.write(concatBytes(head.encodeToByteArray(), init.body))
    // Do not close the duplex here. A full close tears down TLS/Tor reads.
    // The TypeScript client only half-closes the write side; this ByteDuplex
    // has no half-close, and the response is framed by length/chunked.

    val reader = HttpByteReader(init.stream, abort)
    val headBytes = reader.readUntil(CRLFCRLF)
    val headText = headBytes.decodeToString()
    val lines = headText.split("\r\n")
    val statusParts = (lines.firstOrNull() ?: "").split(" ")
    val status = statusParts.getOrNull(1)?.toIntOrNull() ?: 0
    val statusText = statusParts.drop(2).joinToString(" ")
    require(status in 200..599) { "Invalid HTTP status: ${lines.firstOrNull()}" }
    val responseHeaders = LinkedHashMap<String, String>()
    for (line in lines.drop(1)) {
        if (line.isEmpty()) continue
        val colon = line.indexOf(':')
        if (colon == -1) continue
        responseHeaders[line.substring(0, colon).trim()] = line.substring(colon + 1).trim()
    }
    val transfer = responseHeaders.entries.firstOrNull { it.key.equals("Transfer-Encoding", true) }?.value
    progress?.report(FetchStage.DOWNLOADING_RESPONSE)
    var bodyBytes =
        if (transfer != null && transfer.lowercase().contains("chunked")) {
            reader.readChunkedBody()
        } else {
            val lengthHeader =
                responseHeaders.entries.firstOrNull { it.key.equals("Content-Length", true) }?.value
                    ?: throw IllegalArgumentException("HTTP response missing Content-Length and chunked encoding")
            val length = lengthHeader.toIntOrNull()
            require(length != null && length >= 0) { "Invalid Content-Length: $lengthHeader" }
            reader.readExact(length) { have ->
                progress?.downloadBytes(FetchStage.DOWNLOADING_RESPONSE, have, length)
            }
        }
    progress?.report(FetchStage.DOWNLOADING_RESPONSE, 1.0)
    inflateZlibOrNull(bodyBytes)?.let { bodyBytes = it }
    return StreamResponse(status, statusText, responseHeaders, bodyBytes)
}

private val CRLF = "\r\n".encodeToByteArray()
private val CRLFCRLF = "\r\n\r\n".encodeToByteArray()

internal data class HttpsSession(
    val plaintext: ByteDuplex,
    val close: () -> Unit,
)

internal var httpsSessionFactory: (suspend (String, Int, Abort?) -> HttpsSession)? = null

private val httpsLock = Mutex()
private val httpsSessions = LinkedHashMap<Pair<String, Int>, HttpsSession>()

internal suspend fun resetHttpsSessions() {
    resetTlsSessionCache()
    val snapshot =
        httpsLock.withLock {
            val values = httpsSessions.values.toList()
            httpsSessions.clear()
            values
        }
    for (session in snapshot) {
        try {
            session.close()
        } catch (_: Throwable) {
        }
    }
}

@Suppress("LongParameterList")
suspend fun httpsFetch(
    url: String,
    abort: Abort? = null,
    method: String = "GET",
    headers: Map<String, String> = emptyMap(),
    body: ByteArray = ByteArray(0),
    onProgress: FetchProgressListener? = null,
): StreamResponse {
    val reporter = FetchProgressReporter(onProgress)
    return withContext(FetchProgressContext(reporter)) {
        reporter.report(FetchStage.STARTING)
        val parsed = parseUrl(url)
        val key = parsed.host.lowercase() to parsed.port
        var retried = false
        var last: Throwable? = null
        while (true) {
            val session = obtainHttpsSession(key, parsed.host, parsed.port, abort)
            reporter.report(FetchStage.SENDING_REQUEST)
            val first =
                runCatching {
                    streamFetch(url, StreamFetchInit(session.plaintext, abort, headers, method, body))
                }
            keptAlive(key, first)?.let {
                reporter.report(FetchStage.DONE)
                return@withContext it
            }
            last = first.exceptionOrNull()
            val stop =
                last is CoroutineCancellation ||
                    abort?.aborted == true ||
                    last?.message?.contains("closed duplex") == true
            if (!stop) {
                val second =
                    runCatching {
                        streamFetch(url, StreamFetchInit(session.plaintext, abort, headers, method, body))
                    }
                keptAlive(key, second)?.let {
                    reporter.report(FetchStage.DONE)
                    return@withContext it
                }
                last = second.exceptionOrNull()
            }
            evictHttpsSession(key)
            forgetDefaultCircuit(parsed.host, parsed.port)
            if (last is CoroutineCancellation || retried || abort?.aborted == true) break
            retried = true
        }
        throw last ?: Exception("https fetch failed")
    }
}

private fun keepsAlive(res: StreamResponse): Boolean {
    val conn =
        res.headers.entries
            .firstOrNull { it.key.equals("Connection", true) }
            ?.value
    return conn?.contains("keep-alive", ignoreCase = true) == true
}

private suspend fun keptAlive(
    key: Pair<String, Int>,
    result: Result<StreamResponse>,
): StreamResponse? {
    val res = result.getOrNull() ?: return null
    if (!keepsAlive(res)) evictHttpsSession(key)
    return res
}

private suspend fun obtainHttpsSession(
    key: Pair<String, Int>,
    host: String,
    port: Int,
    abort: Abort?,
): HttpsSession {
    httpsLock.withLock { httpsSessions[key] }?.let {
        println("echalote.fetch $host:$port reuse=true")
        return it
    }
    println("echalote.fetch $host:$port reuse=false")
    val opened = (httpsSessionFactory ?: ::openDefaultHttpsSession).invoke(host, port, abort)
    return httpsLock.withLock {
        val existing = httpsSessions[key]
        if (existing != null) {
            try {
                opened.close()
            } catch (_: Throwable) {
            }
            existing
        } else {
            httpsSessions[key] = opened
            opened
        }
    }
}

private suspend fun evictHttpsSession(key: Pair<String, Int>) {
    val session = httpsLock.withLock { httpsSessions.remove(key) } ?: return
    try {
        session.close()
    } catch (_: Throwable) {
    }
}

private suspend fun openDefaultHttpsSession(
    host: String,
    port: Int,
    abort: Abort?,
): HttpsSession {
    val tcp = defaultExitDialer().dial(host, port, abort)
    val tls =
        runCatching { wrapTls(tcp.outer, host, abort) }.getOrElse { err ->
            try {
                tcp.close()
            } catch (_: Throwable) {
            }
            forgetDefaultCircuit(host, port)
            throw err
        }
    fetchProgress()?.report(FetchStage.OPENING_CONNECTION, 1.0)
    return HttpsSession(tls) {
        try {
            tls.close()
        } catch (_: Throwable) {
        }
        try {
            tcp.close()
        } catch (_: Throwable) {
        }
    }
}

private data class ParsedHttpUrl(
    val host: String,
    val port: Int,
    val target: String,
)

private fun parseUrl(input: String): ParsedHttpUrl {
    val s = input
    val schemeEnd = s.indexOf("://")
    val scheme = if (schemeEnd >= 0) s.substring(0, schemeEnd).lowercase() else "https"
    val rest = if (schemeEnd >= 0) s.substring(schemeEnd + 3) else s
    val slash = rest.indexOf('/')
    val hostPort = if (slash < 0) rest else rest.substring(0, slash)
    val path = if (slash < 0) "/" else rest.substring(slash)
    val defaultPort = if (scheme == "http") 80 else 443
    val split = hostPort.lastIndexOf(':')
    val host: String
    val port: Int
    if (split > 0 && !hostPort.startsWith("[")) {
        host = hostPort.substring(0, split)
        port = hostPort.substring(split + 1).toIntOrNull() ?: defaultPort
    } else {
        host = hostPort.trimStart('[').trimEnd(']')
        port = defaultPort
    }
    return ParsedHttpUrl(host, port, path)
}

private class HttpByteReader(
    val duplex: ByteDuplex,
    val abort: Abort?,
) {
    private var buf = ByteArray(0)

    private suspend fun pull() {
        abort?.throwIfAborted()
        val value =
            coroutineScope {
                val reader = async { duplex.read(16 * 1024) }
                abort?.onAbort { reader.cancel() }
                try {
                    reader.await()
                } catch (e: CoroutineCancellation) {
                    abort?.throwIfAborted()
                    throw e
                }
            }
        abort?.throwIfAborted()
        require(value.isNotEmpty()) { "Unexpected end of HTTP stream (buffered=${buf.size})" }
        buf = concatBytes(buf, value)
    }

    suspend fun readUntil(needle: ByteArray): ByteArray {
        while (true) {
            val i = indexOf(buf, needle)
            if (i != -1) {
                val before = buf.copyOfRange(0, i)
                buf = buf.copyOfRange(i + needle.size, buf.size)
                return before
            }
            pull()
        }
    }

    suspend fun readExact(
        n: Int,
        onHave: ((Int) -> Unit)? = null,
    ): ByteArray {
        onHave?.invoke(buf.size.coerceAtMost(n))
        while (buf.size < n) {
            pull()
            onHave?.invoke(buf.size.coerceAtMost(n))
        }
        val out = buf.copyOfRange(0, n)
        buf = buf.copyOfRange(n, buf.size)
        return out
    }

    suspend fun readChunkedBody(): ByteArray {
        val parts = ArrayList<ByteArray>()
        while (true) {
            val sizeLine = readUntil(CRLF).decodeToString()
            val size = sizeLine.trim().toIntOrNull(16) ?: throw IllegalArgumentException("Invalid chunk size")
            if (size == 0) {
                readExact(2)
                break
            }
            parts += readExact(size)
            readExact(2)
        }
        return concatBytes(*parts.toTypedArray())
    }
}

private fun indexOf(
    haystack: ByteArray,
    needle: ByteArray,
    from: Int = 0,
): Int {
    outer@ for (i in from..haystack.size - needle.size) {
        for (j in needle.indices) {
            if (haystack[i + j] != needle[j]) continue@outer
        }
        return i
    }
    return -1
}
