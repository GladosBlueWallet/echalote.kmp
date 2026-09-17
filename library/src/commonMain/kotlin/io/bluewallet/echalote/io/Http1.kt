package io.bluewallet.echalote

data class DirHttpUrl(
    val host: String,
    val port: Int,
    val path: String,
)

/** Tor directory authorities speak HTTP/1.1. Platform HTTPS stacks apply ATS/cleartext bans. */
fun usesCleartextHttp1(url: String): Boolean = url.startsWith("http://")

fun parseHttpUrl(url: String): DirHttpUrl {
    require(url.startsWith("http://")) { "parseHttpUrl expects http://, got $url" }
    val rest = url.removePrefix("http://")
    val slash = rest.indexOf('/')
    val hostPort = if (slash < 0) rest else rest.substring(0, slash)
    val path = if (slash < 0) "/" else rest.substring(slash)
    val colon = hostPort.indexOf(':')
    val host = if (colon < 0) hostPort else hostPort.substring(0, colon)
    val port = if (colon < 0) 80 else hostPort.substring(colon + 1).toInt()
    return DirHttpUrl(host, port, path)
}

fun buildHttp1Request(
    method: String,
    url: DirHttpUrl,
    headers: Map<String, String>,
    body: ByteArray,
): ByteArray {
    val hdr =
        buildString {
            append("$method ${url.path} HTTP/1.1\r\n")
            append("Host: ${url.host}:${url.port}\r\n")
            append("Connection: close\r\n")
            if (headers.keys.none { it.equals("Content-Length", true) }) {
                append("Content-Length: ${body.size}\r\n")
            }
            for ((k, v) in headers) append("$k: $v\r\n")
            append("\r\n")
        }.encodeToByteArray()
    return if (body.isEmpty()) hdr else hdr + body
}

fun parseHttp1Response(raw: ByteArray): HttpResponse {
    val text = raw.decodeToString()
    val split = text.indexOf("\r\n\r\n")
    require(split >= 0) { "HTTP response missing header terminator" }
    val head = text.substring(0, split)
    val body = raw.copyOfRange(split + 4, raw.size)
    val lines = head.split("\r\n")
    val status = lines[0].split(" ").getOrNull(1)?.toIntOrNull() ?: 0
    val headers = mutableMapOf<String, String>()
    for (line in lines.drop(1)) {
        val c = line.indexOf(':')
        if (c > 0) headers[line.substring(0, c).trim()] = line.substring(c + 1).trim()
    }
    val length =
        headers.entries
            .firstOrNull { it.key.equals("Content-Length", true) }
            ?.value
            ?.toIntOrNull()
    val sliced = if (length != null) body.copyOf(minOf(length, body.size)) else body
    return HttpResponse(status, sliced, headers)
}

fun http1HeaderEnd(raw: ByteArray): Int {
    val last = raw.size - 3
    var i = 0
    while (i < last) {
        if (
            raw[i] == 0x0d.toByte() &&
            raw[i + 1] == 0x0a.toByte() &&
            raw[i + 2] == 0x0d.toByte() &&
            raw[i + 3] == 0x0a.toByte()
        ) {
            return i
        }
        i++
    }
    return -1
}

internal const val MAX_HTTP1_BODY = 16 * 1024 * 1024

fun http1HeaderValue(
    headerBytes: ByteArray,
    name: String,
): String? {
    val text = headerBytes.decodeToString()
    for (line in text.split("\r\n").drop(1)) {
        val c = line.indexOf(':')
        if (c <= 0) continue
        if (line.substring(0, c).trim().equals(name, ignoreCase = true)) {
            return line.substring(c + 1).trim()
        }
    }
    return null
}

fun http1ContentLength(headerBytes: ByteArray): Int? = http1HeaderValue(headerBytes, "Content-Length")?.toIntOrNull()

fun http1MessageComplete(raw: ByteArray): Boolean {
    val split = http1HeaderEnd(raw)
    if (split < 0) return false
    val length = http1ContentLength(raw.copyOf(split)) ?: return false
    return raw.size - split - 4 >= length
}

fun readHttp1Raw(
    maxBody: Int = MAX_HTTP1_BODY,
    read: () -> ByteArray?,
): ByteArray {
    val chunks = ArrayList<ByteArray>()
    var total = 0
    while (true) {
        val chunk = read() ?: throw IllegalArgumentException("HTTP response missing header terminator")
        if (chunk.isEmpty()) continue
        chunks += chunk
        total += chunk.size
        val soFar = concatBytes(*chunks.toTypedArray())
        val headerEnd = http1HeaderEnd(soFar)
        if (headerEnd < 0) {
            require(total <= 256 * 1024) { "HTTP headers too large" }
            continue
        }
        val headers = soFar.copyOf(headerEnd)
        val transfer = http1HeaderValue(headers, "Transfer-Encoding")
        if (transfer != null && transfer.contains("chunked", ignoreCase = true)) {
            throw IllegalArgumentException("chunked Transfer-Encoding is not supported")
        }
        val length = parseHttp1ContentLength(http1HeaderValue(headers, "Content-Length"), maxBody)
        var haveBody = soFar.size - headerEnd - 4
        if (length == null) {
            require(haveBody <= maxBody) { "HTTP body too large" }
            while (true) {
                val more = read() ?: break
                if (more.isEmpty()) continue
                haveBody += more.size
                require(haveBody <= maxBody) { "HTTP body too large" }
                chunks += more
            }
            return concatBytes(*chunks.toTypedArray())
        }
        while (haveBody < length) {
            val more = read() ?: throw IllegalArgumentException("truncated HTTP body")
            if (more.isEmpty()) continue
            chunks += more
            haveBody += more.size
        }
        return concatBytes(*chunks.toTypedArray())
    }
}

private fun parseHttp1ContentLength(
    value: String?,
    maxBody: Int,
): Int? {
    if (value == null) return null
    val n = value.toLongOrNull() ?: throw IllegalArgumentException("Invalid Content-Length: $value")
    require(n >= 0) { "Invalid Content-Length: $n" }
    require(n <= maxBody) { "HTTP body too large: $n" }
    return n.toInt()
}
