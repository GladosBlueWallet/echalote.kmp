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
    val persistent: Boolean = false,
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
    if (init.headers.keys.none { it.equals("Accept-Encoding", true) }) {
        headers["Accept-Encoding"] = "identity"
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
    return HttpByteReader(init.stream, abort).readResponse(progress)
}

private val CRLF = "\r\n".encodeToByteArray()
private val CRLFCRLF = "\r\n\r\n".encodeToByteArray()

internal class HttpsSession(
    val plaintext: ByteDuplex,
    val close: () -> Unit,
) {
    val io = Mutex()
}

internal class HttpStreamException(
    message: String,
    val reusable: Boolean,
) : IllegalArgumentException(message)

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
                    session.io.withLock {
                        streamFetch(url, StreamFetchInit(session.plaintext, abort, headers, method, body))
                    }
                }
            keptAlive(key, first)?.let {
                reporter.report(FetchStage.DONE)
                return@withContext it
            }
            last = first.exceptionOrNull()
            val failure = last
            val reusable = failure is HttpStreamException && failure.reusable
            if (reusable && abort?.aborted != true) {
                val second =
                    runCatching {
                        session.io.withLock {
                            streamFetch(url, StreamFetchInit(session.plaintext, abort, headers, method, body))
                        }
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

private fun keepsAlive(res: StreamResponse): Boolean = res.persistent

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
    val host: String
    val port: Int
    if (hostPort.startsWith("[")) {
        val end = hostPort.indexOf(']')
        require(end > 1) { "bad ipv6 url" }
        host = hostPort.substring(1, end)
        port =
            if (end + 1 < hostPort.length && hostPort[end + 1] == ':') {
                hostPort.substring(end + 2).toIntOrNull() ?: defaultPort
            } else {
                defaultPort
            }
    } else {
        val split = hostPort.lastIndexOf(':')
        if (split > 0) {
            host = hostPort.substring(0, split)
            port = hostPort.substring(split + 1).toIntOrNull() ?: defaultPort
        } else {
            host = hostPort
            port = defaultPort
        }
    }
    return ParsedHttpUrl(host, port, path)
}

private class HttpByteReader(
    val duplex: ByteDuplex,
    val abort: Abort?,
) {
    suspend fun readResponse(progress: FetchProgressReporter?): StreamResponse {
        val headText = readUntil(CRLFCRLF).decodeToString()
        val lines = headText.split("\r\n")
        val statusLine = lines.firstOrNull() ?: ""
        val statusParts = statusLine.split(" ")
        val status = statusParts.getOrNull(1)?.toIntOrNull() ?: 0
        val statusText = statusParts.drop(2).joinToString(" ")
        require(status in 200..599) { "Invalid HTTP status: $statusLine" }
        val responseHeaders = LinkedHashMap<String, String>()
        val contentLengths = ArrayList<String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            if (line.isNotEmpty() && colon > 0) {
                val name = line.substring(0, colon).trim()
                val value = line.substring(colon + 1).trim()
                if (name.equals("Content-Length", true)) contentLengths += value
                responseHeaders[name] = value
            }
        }
        require(contentLengths.map { it.trim() }.distinct().size <= 1) { "conflicting Content-Length" }
        progress?.report(FetchStage.DOWNLOADING_RESPONSE)
        val bodyBytes = readBody(statusLine, responseHeaders, contentLengths, progress)
        progress?.report(FetchStage.DOWNLOADING_RESPONSE, 1.0)
        return finishResponse(status, statusText, statusLine, responseHeaders, bodyBytes)
    }

    private fun finishResponse(
        status: Int,
        statusText: String,
        statusLine: String,
        responseHeaders: Map<String, String>,
        bodyBytes: ByteArray,
    ): StreamResponse {
        val connection = responseHeaders.entries.firstOrNull { it.key.equals("Connection", true) }?.value
        val keep =
            when {
                connection?.contains("close", ignoreCase = true) == true -> false
                connection?.contains("keep-alive", ignoreCase = true) == true -> true
                else -> !statusLine.startsWith("HTTP/1.0")
            }
        val encoding =
            responseHeaders.entries
                .firstOrNull { it.key.equals("Content-Encoding", true) }
                ?.value
                ?.lowercase()
        val decoded =
            when {
                encoding == null || encoding == "identity" || encoding.isEmpty() -> bodyBytes
                encoding.contains("deflate") || encoding.contains("zlib") ->
                    inflateZlibOrNull(bodyBytes) ?: error("bad zlib body")
                else -> error("unsupported Content-Encoding: $encoding")
            }
        return StreamResponse(status, statusText, responseHeaders, decoded, keep)
    }

    private suspend fun readBody(
        statusLine: String,
        responseHeaders: Map<String, String>,
        contentLengths: List<String>,
        progress: FetchProgressReporter?,
    ): ByteArray {
        val transfer = responseHeaders.entries.firstOrNull { it.key.equals("Transfer-Encoding", true) }?.value
        val lengthHeader = contentLengths.firstOrNull()
        val connection = responseHeaders.entries.firstOrNull { it.key.equals("Connection", true) }?.value
        val untilClose = statusLine.startsWith("HTTP/1.0") || connection?.contains("close", ignoreCase = true) == true
        val chunked = transfer != null && transfer.lowercase().contains("chunked")
        return if (chunked) {
            readChunkedBody()
        } else if (lengthHeader == null && untilClose) {
            readUntilEof { have -> progress?.downloadBytes(FetchStage.DOWNLOADING_RESPONSE, have, null) }
        } else {
            require(lengthHeader != null) { "HTTP response missing Content-Length and chunked encoding" }
            val length = lengthHeader.toLongOrNull()
            require(length != null && length >= 0) { "Invalid Content-Length: $lengthHeader" }
            require(length <= MAX_HTTP1_BODY) { "HTTP body too large: $length" }
            readExact(length.toInt()) { have ->
                progress?.downloadBytes(FetchStage.DOWNLOADING_RESPONSE, have, length.toInt())
            }
        }
    }

    private var buf = ByteArray(0)
    private var len = 0
    private var receivedAny = false

    private fun append(value: ByteArray) {
        receivedAny = true
        val need = len + value.size
        require(need <= MAX_HTTP1_BODY) { "HTTP body too large" }
        if (buf.size < need) {
            var cap = if (buf.isEmpty()) 256 else buf.size
            while (cap < need) cap *= 2
            buf = buf.copyOf(cap)
        }
        value.copyInto(buf, len)
        len += value.size
    }

    private fun consume(n: Int): ByteArray {
        val out = buf.copyOfRange(0, n)
        buf.copyInto(buf, 0, n, len)
        len -= n
        return out
    }

    private suspend fun pull(eofOk: Boolean): Boolean {
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
        if (value.isEmpty()) {
            if (eofOk) return false
            throw HttpStreamException(
                "Unexpected end of HTTP stream (buffered=$len)",
                reusable = !receivedAny,
            )
        }
        append(value)
        return true
    }

    suspend fun readUntil(
        needle: ByteArray,
        max: Int = 256 * 1024,
    ): ByteArray {
        while (true) {
            val i = indexOf(buf, needle, 0, len)
            if (i != -1) return consume(i).also { consume(needle.size) }
            if (len > max) throw HttpStreamException("HTTP headers too large", reusable = false)
            pull(eofOk = false)
        }
    }

    suspend fun readExact(
        n: Int,
        onHave: ((Int) -> Unit)? = null,
    ): ByteArray {
        onHave?.invoke(len.coerceAtMost(n))
        while (len < n) {
            pull(eofOk = false)
            onHave?.invoke(len.coerceAtMost(n))
        }
        return consume(n)
    }

    suspend fun readUntilEof(onHave: ((Int) -> Unit)? = null): ByteArray {
        while (pull(eofOk = true)) {
            onHave?.invoke(len)
        }
        return consume(len)
    }

    suspend fun readChunkedBody(): ByteArray {
        val parts = ArrayList<ByteArray>()
        var total = 0
        while (true) {
            val sizeLine = readUntil(CRLF).decodeToString()
            val sizeToken = sizeLine.substringBefore(';').trim()
            val size = sizeToken.toIntOrNull(16) ?: throw IllegalArgumentException("Invalid chunk size")
            require(size >= 0) { "Invalid chunk size" }
            if (size == 0) {
                while (readUntil(CRLF).isNotEmpty()) {
                    // trailers
                }
                break
            }
            require(total.toLong() + size <= MAX_HTTP1_BODY) { "HTTP body too large" }
            val chunk = readExact(size)
            val crlf = readExact(2)
            require(crlf.size == 2 && crlf[0] == 0x0d.toByte() && crlf[1] == 0x0a.toByte()) {
                "chunk missing CRLF"
            }
            parts += chunk
            total += size
        }
        return concatBytes(*parts.toTypedArray())
    }
}

private fun indexOf(
    haystack: ByteArray,
    needle: ByteArray,
    from: Int = 0,
    end: Int = haystack.size,
): Int {
    outer@ for (i in from..end - needle.size) {
        for (j in needle.indices) {
            if (haystack[i + j] != needle[j]) continue@outer
        }
        return i
    }
    return -1
}
