package io.bluewallet.echalote

data class DirHttpUrl(val host: String, val port: Int, val path: String)

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
    val hdr = buildString {
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
    val length = headers.entries.firstOrNull { it.key.equals("Content-Length", true) }?.value?.toIntOrNull()
    val sliced = if (length != null) body.copyOf(minOf(length, body.size)) else body
    return HttpResponse(status, sliced, headers)
}
