package io.bluewallet.echalote

import kotlin.time.Duration

/** One `echalote.http.timing` line per cleartext HTTP/1 request: connect, first byte, body. */
internal class Http1Timing(
    private val url: String,
    private val enabled: Boolean = true,
) {
    private val start = timeMark()
    private var connectedAt: Duration? = null
    private var firstByteAt: Duration? = null

    fun connected() {
        connectedAt = start.elapsedNow()
    }

    fun firstByte() {
        if (firstByteAt == null) firstByteAt = start.elapsedNow()
    }

    fun done(res: HttpResponse) {
        if (!enabled) return
        val total = start.elapsedNow()
        val connect = connectedAt ?: Duration.ZERO
        val first = firstByteAt ?: total
        val encoding =
            res.headers.entries
                .firstOrNull { it.key.equals("Content-Encoding", ignoreCase = true) }
                ?.value ?: "none"
        logTiming(
            "http",
            "request",
            total,
            "url=${url.substringAfter("://").take(MAX_URL)} status=${res.status} bytes=${res.body.size} " +
                "connect=${connect.msText()} ttfb=${(first - connect).msText()} body=${(total - first).msText()} " +
                "encoding=$encoding",
        )
    }

    private companion object {
        const val MAX_URL = 80
    }
}
