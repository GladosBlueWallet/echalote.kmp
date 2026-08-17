package io.bluewallet.echalote

import kotlinx.coroutines.CancellationException as CoroutineCancellation
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope


data class StreamFetchInit(
    val stream: ByteDuplex,
    val abort: Abort? = null,
    val headers: Map<String, String> = emptyMap(),
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
        fun skipWs() { while (i < inner.length && inner[i].isWhitespace()) i++ }
        while (i < inner.length) {
            skipWs()
            require(inner[i] == '"') { "expected key" }
            i++
            val ks = i
            while (inner[i] != '"') i++
            val key = inner.substring(ks, i)
            i++
            skipWs(); require(inner[i] == ':'); i++; skipWs()
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

suspend fun streamFetch(input: String, init: StreamFetchInit): StreamResponse {
    val abort = init.abort
    abort?.throwIfAborted()
    val url = parseUrl(input)
    val headers = LinkedHashMap<String, String>()
    if (init.headers.keys.none { it.equals("Host", true) }) headers["Host"] = url.host
    if (init.headers.keys.none { it.equals("Connection", true) }) headers["Connection"] = "close"
    headers.putAll(init.headers)
    val head = buildString {
        append("GET ${url.target} HTTP/1.1\r\n")
        for ((k, v) in headers) append("$k: $v\r\n")
        append("\r\n")
    }
    init.stream.write(head.encodeToByteArray())
    try {
        init.stream.close()
    } catch (_: Throwable) {
    }

    val reader = HttpByteReader(init.stream, abort)
    val headBytes = reader.readUntil(CRLFCRLF)
    val headText = headBytes.decodeToString()
    val lines = headText.split("\r\n")
    val statusParts = (lines.firstOrNull() ?: "").split(" ")
    val status = statusParts.getOrNull(1)?.toIntOrNull() ?: 0
    val statusText = statusParts.drop(2).joinToString(" ")
    if (status !in 200..599) throw IllegalArgumentException("Invalid HTTP status: ${lines.firstOrNull()}")
    val responseHeaders = LinkedHashMap<String, String>()
    for (line in lines.drop(1)) {
        if (line.isEmpty()) continue
        val colon = line.indexOf(':')
        if (colon == -1) continue
        responseHeaders[line.substring(0, colon).trim()] = line.substring(colon + 1).trim()
    }
    val transfer = responseHeaders.entries.firstOrNull { it.key.equals("Transfer-Encoding", true) }?.value
    var bodyBytes = if (transfer != null && transfer.lowercase().contains("chunked")) {
        reader.readChunkedBody()
    } else {
        val lengthHeader = responseHeaders.entries.firstOrNull { it.key.equals("Content-Length", true) }?.value
            ?: throw IllegalArgumentException("HTTP response missing Content-Length and chunked encoding")
        val length = lengthHeader.toIntOrNull() ?: throw IllegalArgumentException("Invalid Content-Length: $lengthHeader")
        if (length < 0) throw IllegalArgumentException("Invalid Content-Length: $lengthHeader")
        reader.readExact(length)
    }
    inflateZlibOrNull(bodyBytes)?.let { bodyBytes = it }
    return StreamResponse(status, statusText, responseHeaders, bodyBytes)
}

private val CRLF = "\r\n".encodeToByteArray()
private val CRLFCRLF = "\r\n\r\n".encodeToByteArray()

private data class ParsedHttpUrl(val host: String, val target: String)

private fun parseUrl(input: String): ParsedHttpUrl {
    val s = input
    val schemeEnd = s.indexOf("://")
    val rest = if (schemeEnd >= 0) s.substring(schemeEnd + 3) else s
    val slash = rest.indexOf('/')
    val hostPort = if (slash < 0) rest else rest.substring(0, slash)
    val path = if (slash < 0) "/" else rest.substring(slash)
    return ParsedHttpUrl(hostPort, path)
}

private class HttpByteReader(val duplex: ByteDuplex, val abort: Abort?) {
    private var buf = ByteArray(0)

    private suspend fun pull() {
        abort?.throwIfAborted()
        val value = coroutineScope {
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
        if (value.isEmpty()) throw IllegalArgumentException("Unexpected end of HTTP stream")
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

    suspend fun readExact(n: Int): ByteArray {
        while (buf.size < n) pull()
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

private fun indexOf(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
    outer@ for (i in from..haystack.size - needle.size) {
        for (j in needle.indices) {
            if (haystack[i + j] != needle[j]) continue@outer
        }
        return i
    }
    return -1
}
