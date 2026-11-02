package io.bluewallet.echalote

// No socket transport on this platform yet: direct relay mode falls back to meek.
internal actual suspend fun platformTcpConnect(
    host: String,
    port: Int,
    timeoutMs: Long,
): ByteDuplex? = null
