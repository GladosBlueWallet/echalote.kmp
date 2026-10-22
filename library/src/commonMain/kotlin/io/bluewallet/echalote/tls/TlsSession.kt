package io.bluewallet.echalote

internal const val TLS_SESSION_TICKET_EXT = 0x0023

/**
 * Longest a verified session may be resumed. Resumption skips certificate checks, so this
 * also bounds how long a full-handshake verification is trusted; past it a full handshake
 * (with chain verification) is forced.
 */
internal const val MAX_TLS_RESUME_TTL_MS = 2L * 60L * 60L * 1000L

internal data class TlsResumption(
    val host: String,
    val master: ByteArray,
    val sessionId: ByteArray,
    val ticket: ByteArray,
    val ems: Boolean,
    val expiresAtMs: Long,
)

internal data class ParsedSessionTicket(
    val lifetimeHintSec: Long,
    val ticket: ByteArray,
)

internal data class ParsedServerHello(
    val serverRandom: ByteArray,
    val sessionId: ByteArray,
    val ems: Boolean,
)

private val tlsSessions = LinkedHashMap<String, TlsResumption>()
private val tlsSessionLock = SpinLock()

internal fun parseNewSessionTicket(body: ByteArray): ParsedSessionTicket {
    require(body.size >= 6) { "short NewSessionTicket" }
    val lifetime = body.u32be(0).toLong() and 0xffffffffL
    val len = body.u16be(4)
    require(body.size >= 6 + len) { "truncated NewSessionTicket" }
    return ParsedSessionTicket(lifetime, body.copyOfRange(6, 6 + len))
}

internal fun parseServerHello(body: ByteArray): ParsedServerHello {
    require(body.size >= 35) { "short ServerHello" }
    require(body.u16be(0) == 0x0303) { "unsupported TLS version ${body.u16be(0)}" }
    val serverRandom = body.copyOfRange(2, 34)
    var o = 34
    val sidLen = body.u8(o)
    o += 1
    require(sidLen <= 32 && o + sidLen <= body.size) { "bad ServerHello session id" }
    val sessionId = body.copyOfRange(o, o + sidLen)
    o += sidLen
    require(o + 3 <= body.size) { "short ServerHello suite" }
    val suite = body.u16be(o)
    o += 2
    require(suite == TLS_ECDHE_RSA_AES256_GCM_SHA384) { "unexpected cipher $suite" }
    require(body.u8(o) == 0) { "unexpected TLS compression" }
    o += 1
    var ems = false
    if (o + 2 <= body.size) {
        val extLen = body.u16be(o)
        o += 2
        val end = o + extLen
        require(end <= body.size) { "truncated ServerHello extensions" }
        while (o + 4 <= end) {
            val et = body.u16be(o)
            val el = body.u16be(o + 2)
            o += 4
            require(o + el <= end) { "truncated ServerHello extension" }
            if (et == 0x0017) ems = true
            o += el
        }
    }
    return ParsedServerHello(serverRandom, sessionId, ems)
}

internal fun rememberTlsSession(session: TlsResumption) {
    val key = session.host.lowercase()
    val copy =
        session.copy(
            host = key,
            master = session.master.copyOf(),
            sessionId = session.sessionId.copyOf(),
            ticket = session.ticket.copyOf(),
        )
    tlsSessionLock.withLock { tlsSessions[key] = copy }
}

internal fun lookupTlsSession(
    host: String,
    nowMs: Long = currentEpochMillis(),
): TlsResumption? =
    tlsSessionLock.withLock {
        val key = host.lowercase()
        val hit = tlsSessions[key]
        if (hit != null && nowMs >= hit.expiresAtMs) {
            tlsSessions.remove(key)
        }
        val live =
            hit != null &&
                nowMs < hit.expiresAtMs &&
                (hit.ticket.isNotEmpty() || hit.sessionId.isNotEmpty())
        hit.takeIf { live }
    }

internal fun forgetTlsSession(host: String) {
    tlsSessionLock.withLock { tlsSessions.remove(host.lowercase()) }
}

internal fun resetTlsSessionCache() {
    tlsSessionLock.withLock { tlsSessions.clear() }
}

/**
 * Expiry for a cached session: the server's ticket lifetime hint, capped at
 * [MAX_TLS_RESUME_TTL_MS] (a zero hint means "unspecified" and gets the cap), and never past
 * [ceilingMs]. Callers pass the leaf's notAfter for a full handshake and the cached expiry for a
 * resumption, so a resumed session can never outlive the verification it came from.
 */
internal fun tlsResumeExpiryMs(
    lifetimeHintSec: Long,
    nowMs: Long = currentEpochMillis(),
    ceilingMs: Long = Long.MAX_VALUE,
): Long {
    val hintMs = lifetimeHintSec.coerceIn(0L, MAX_TLS_RESUME_TTL_MS / 1000L) * 1000L
    val ttl = if (hintMs > 0L) hintMs else MAX_TLS_RESUME_TTL_MS
    return minOf(nowMs + ttl, ceilingMs)
}

/**
 * Latest instant a session verified on [chainDer] may be resumed: the earliest notAfter in the
 * chain, since the path dies with its first certificate. Certificates already expired at [nowMs]
 * cannot be on the path the platform just validated (e.g. a stale cross-sign), so they are skipped.
 * A certificate we cannot parse makes the session non-resumable (returns [nowMs]).
 */
internal fun chainResumeCeilingMs(
    chainDer: List<ByteArray>,
    nowMs: Long = currentEpochMillis(),
): Long {
    val notAfters = chainDer.map { der -> runCatching { X509Certificate.parse(der).notAfterMillis }.getOrNull() }
    if (notAfters.isEmpty() || notAfters.any { it == null }) return nowMs
    return notAfters.filterNotNull().filter { it >= nowMs }.minOrNull() ?: nowMs
}

internal fun storeTlsResumption(session: TlsResumption) {
    if (session.host.isEmpty()) return
    if (session.ticket.isEmpty() && session.sessionId.isEmpty()) return
    rememberTlsSession(session)
}
