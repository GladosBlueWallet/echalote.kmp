package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL

actual fun defaultHttpEngine(): HttpEngine = HttpEngine { method, url, headers, body, timeoutMs, decompress ->
    withContext(Dispatchers.IO) {
        if (url.startsWith("http://")) {
            http1OverTcp(method, url, headers, body, timeoutMs)
        } else {
            httpsUrlConnection(method, url, headers, body, timeoutMs, decompress)
        }
    }
}

private fun http1OverTcp(
    method: String,
    url: String,
    headers: Map<String, String>,
    body: ByteArray,
    timeoutMs: Long,
): HttpResponse {
    val parsed = parseHttpUrl(url)
    val timeout = timeoutMs.toInt().coerceAtLeast(1)
    Socket().use { sock ->
        sock.soTimeout = timeout
        sock.connect(InetSocketAddress(parsed.host, parsed.port), timeout)
        val req = buildHttp1Request(method, parsed, headers, body)
        sock.getOutputStream().write(req)
        sock.getOutputStream().flush()
        val raw = sock.getInputStream().readBytes()
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
): HttpResponse {
    val conn = (URL(url).openConnection() as HttpURLConnection).apply {
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
        val bytes = stream?.readBytes() ?: ByteArray(0)
        val hdrs = mutableMapOf<String, String>()
        for ((k, vs) in conn.headerFields) {
            if (k != null && vs != null && vs.isNotEmpty()) hdrs[k] = vs.joinToString(", ")
        }
        return HttpResponse(status, bytes, hdrs)
    } finally {
        conn.disconnect()
    }
}
