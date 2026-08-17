package io.bluewallet.echalote

data class HttpResponse(val status: Int, val body: ByteArray, val headers: Map<String, String> = emptyMap())

interface HttpEngine {
    suspend fun request(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        timeoutMs: Long,
        decompress: Boolean,
    ): HttpResponse
}

suspend fun HttpEngine.call(
    method: String,
    url: String,
    headers: Map<String, String> = emptyMap(),
    body: ByteArray = ByteArray(0),
    timeoutMs: Long = 30_000,
    decompress: Boolean = true,
): HttpResponse = request(method, url, headers, body, timeoutMs, decompress)

fun HttpEngine(
    block: suspend (
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        timeoutMs: Long,
        decompress: Boolean,
    ) -> HttpResponse,
): HttpEngine = object : HttpEngine {
    override suspend fun request(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        timeoutMs: Long,
        decompress: Boolean,
    ): HttpResponse = block(method, url, headers, body, timeoutMs, decompress)
}

expect fun defaultHttpEngine(): HttpEngine
