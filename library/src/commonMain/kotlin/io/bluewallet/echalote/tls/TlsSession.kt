package io.bluewallet.echalote

internal const val TLS_SESSION_TICKET_EXT = 0x0023
private const val DEFAULT_TICKET_TTL_MS = 2L * 60L * 60L * 1000L

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

internal fun parseNewSessionTicket(body: ByteArray): ParsedSessionTicket {
    require(body.size >= 6) { "short NewSessionTicket" }
    val lifetime = body.u32be(0).toLong() and 0xffffffffL
    val len = body.u16be(4)
    require(body.size >= 6 + len) { "truncated NewSessionTicket" }
    return ParsedSessionTicket(lifetime, body.copyOfRange(6, 6 + len))
}

internal fun parseServerHello(body: ByteArray): ParsedServerHello {
    require(body.size >= 34) { "short ServerHello" }
    val serverRandom = body.copyOfRange(2, 34)
    var o = 34
    val sidLen = body.u8(o)
    o += 1
    val sessionId = body.copyOfRange(o, o + sidLen)
    o += sidLen
    require(o + 3 <= body.size) { "short ServerHello suite" }
    val suite = body.u16be(o)
    o += 2
    require(suite == TLS_ECDHE_RSA_AES256_GCM_SHA384) { "unexpected cipher $suite" }
    o += 1
    var ems = false
    if (o + 2 <= body.size) {
        val extLen = body.u16be(o)
        o += 2
        val end = o + extLen
        while (o + 4 <= end) {
            val et = body.u16be(o)
            val el = body.u16be(o + 2)
            o += 4
            if (et == 0x0017) ems = true
            o += el
        }
    }
    return ParsedServerHello(serverRandom, sessionId, ems)
}

internal fun rememberTlsSession(session: TlsResumption) {
    val key = session.host.lowercase()
    tlsSessions[key] =
        session.copy(
            host = key,
            master = session.master.copyOf(),
            sessionId = session.sessionId.copyOf(),
            ticket = session.ticket.copyOf(),
        )
}

internal fun lookupTlsSession(
    host: String,
    nowMs: Long = currentEpochMillis(),
): TlsResumption? {
    val key = host.lowercase()
    val hit = tlsSessions[key]
    if (hit != null && nowMs >= hit.expiresAtMs) {
        tlsSessions.remove(key)
    }
    val live =
        hit != null &&
            nowMs < hit.expiresAtMs &&
            (hit.ticket.isNotEmpty() || hit.sessionId.isNotEmpty())
    return hit.takeIf { live }
}

internal fun forgetTlsSession(host: String) {
    tlsSessions.remove(host.lowercase())
}

internal fun resetTlsSessionCache() {
    tlsSessions.clear()
}

internal fun tlsResumeExpiryMs(
    lifetimeHintSec: Long,
    nowMs: Long = currentEpochMillis(),
): Long {
    val ttl = if (lifetimeHintSec > 0L) lifetimeHintSec * 1000L else DEFAULT_TICKET_TTL_MS
    return nowMs + ttl
}

internal fun storeTlsResumption(session: TlsResumption) {
    if (session.host.isEmpty()) return
    if (session.ticket.isEmpty() && session.sessionId.isEmpty()) return
    rememberTlsSession(session)
}
