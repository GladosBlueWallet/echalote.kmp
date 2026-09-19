package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

actual fun defaultHttpEngine(): HttpEngine =
    HttpEngine { method, url, headers, body, timeoutMs, decompress ->
        val onDownload = http1ProgressSink()
        withContext(Dispatchers.IO) {
            if (usesCleartextHttp1(url)) {
                http1OverTcp(method, url, headers, body, timeoutMs, onDownload)
            } else {
                httpsUrlConnection(method, url, headers, body, timeoutMs, decompress, onDownload)
            }
        }
    }

private fun http1OverTcp(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
    onDownload: ((Int, Int?) -> Unit)?,
): HttpResponse {
    val parsed = parseHttpUrl(url)
    val timeout = timeoutMs.toInt().coerceAtLeast(1)
    Socket().use { sock ->
        sock.soTimeout = timeout
        sock.connect(InetSocketAddress(parsed.host, parsed.port), timeout)
        val req = buildHttp1Request(method, parsed, headers, body)
        sock.getOutputStream().write(req)
        sock.getOutputStream().flush()
        val input = sock.getInputStream()
        val buf = ByteArray(16 * 1024)
        val raw =
            readHttp1Raw(onDownload = onDownload) {
                val n = input.read(buf)
                if (n < 0) null else buf.copyOf(n)
            }
        return parseHttp1Response(raw)
    }
}

private fun httpsUrlConnection(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
    decompress: Boolean,
    onDownload: ((Int, Int?) -> Unit)?,
): HttpResponse {
    val conn =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMs.toInt().coerceAtLeast(1)
            readTimeout = timeoutMs.toInt().coerceAtLeast(1)
            instanceFollowRedirects = true
            doInput = true
            useCaches = false
            if (!decompress) {
                setRequestProperty("Accept-Encoding", "identity")
            }
            for ((k, v) in headers) setRequestProperty(k, v)
            if (method == "POST" || body.isNotEmpty()) {
                doOutput = true
                outputStream.use { it.write(body) }
            }
        }
    try {
        val status = conn.responseCode
        val stream = if (status in 200..299) conn.inputStream else conn.errorStream
        val tick = if (status in 200..299) onDownload else null
        val bytes = readStreamProgress(stream, conn.contentLength, tick)
        val hdrs = mutableMapOf<String, String>()
        for ((k, vs) in conn.headerFields) {
            if (k != null && vs != null && vs.isNotEmpty()) hdrs[k] = vs.joinToString(", ")
        }
        return HttpResponse(status, bytes, hdrs)
    } finally {
        conn.disconnect()
    }
}

private fun readStreamProgress(
    stream: java.io.InputStream?,
    contentLength: Int,
    onDownload: ((Int, Int?) -> Unit)?,
): ByteArray {
    if (stream == null) return ByteArray(0)
    val total = contentLength.takeIf { it > 0 }
    val out = java.io.ByteArrayOutputStream(total ?: 16 * 1024)
    val buf = ByteArray(16 * 1024)
    var received = 0
    while (true) {
        val n = stream.read(buf)
        if (n < 0) break
        out.write(buf, 0, n)
        received += n
        onDownload?.invoke(received, total)
    }
    return out.toByteArray()
}
