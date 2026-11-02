package io.bluewallet.echalote

/**
 * Opens a plain TCP connection, for talking to a Tor relay's ORPort directly (opt-in, see
 * [ExitDialerOptions.directGuard]). Returns null where the platform has no socket support
 * yet, so callers fall back to meek. Throws if the connection itself fails.
 */
internal expect suspend fun platformTcpConnect(
    host: String,
    port: Int,
    timeoutMs: Long,
): ByteDuplex?
