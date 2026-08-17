package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

actual fun defaultHttpEngine(): HttpEngine = HttpEngine { method, url, headers, body, timeoutMs, decompress ->
    withContext(Dispatchers.IO) {
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
            val status = try {
                conn.responseCode
            } catch (_: Exception) {
                0
            }
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val bytes = stream?.readBytes() ?: ByteArray(0)
            val hdrs = mutableMapOf<String, String>()
            for ((k, vs) in conn.headerFields) {
                if (k != null && vs != null && vs.isNotEmpty()) hdrs[k] = vs.joinToString(", ")
            }
            HttpResponse(status, bytes, hdrs)
        } finally {
            conn.disconnect()
        }
    }
}
