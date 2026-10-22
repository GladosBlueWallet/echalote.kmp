package io.bluewallet.echalote

private const val IPV6_WORDS = 8
private const val IPV6_BYTES = 16

/** Canonical dotted-quad IPv4 only: four decimal parts, 0..255, no leading zeros. */
internal fun parseIpv4(host: String): ByteArray? {
    val parts = host.split('.')
    val octets =
        parts.mapNotNull { part ->
            val canonical = part.length in 1..3 && part.all { c -> c in '0'..'9' } && (part.length == 1 || part[0] != '0')
            part.takeIf { canonical }?.toInt()?.takeIf { it <= 255 }
        }
    return if (parts.size == 4 && octets.size == 4) ByteArray(4) { i -> octets[i].toByte() } else null
}

/** A DNS name never has an all-digit top-level label (RFC 3696 §2), so such a host is an IP-ish literal. */
internal fun looksNumeric(host: String): Boolean {
    val last = host.trimEnd('.').substringAfterLast('.')
    return last.isNotEmpty() && last.all { it in '0'..'9' }
}

/** IPv4 dotted quad, or IPv6 text (RFC 4291 §2.2, optionally in brackets), as 4 or 16 bytes. */
internal fun parseIpLiteral(host: String): ByteArray? {
    val h = host.trimEnd('.')
    return when {
        h.startsWith('[') -> if (h.endsWith(']')) parseIpv6(h.substring(1, h.length - 1)) else null
        h.contains(':') -> parseIpv6(h)
        else -> parseIpv4(h)
    }
}

private fun parseIpv6(text: String): ByteArray? {
    val halves = text.split("::")
    val compressed = halves.size == 2
    // Zone ids ("%eth0") never appear in certificates.
    val valid = text.isNotEmpty() && !text.contains('%') && halves.size <= 2
    val head = if (valid) ipv6Groups(halves[0], allowTrailingIpv4 = !compressed) else null
    val tail = if (compressed) ipv6Groups(halves[1], allowTrailingIpv4 = true) else emptyList()
    val words = head.orEmpty().size + tail.orEmpty().size
    val fits = head != null && tail != null && (if (compressed) words < IPV6_WORDS else words == IPV6_WORDS)
    if (!fits) return null
    val all = head.orEmpty() + List(IPV6_WORDS - words) { 0 } + tail.orEmpty()
    return ByteArray(IPV6_BYTES) { i -> (all[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }
}

/** Colon-separated 16-bit groups; a dotted-quad last group counts as two groups. */
private fun ipv6Groups(
    part: String,
    allowTrailingIpv4: Boolean,
): List<Int>? {
    if (part.isEmpty()) return emptyList()
    val pieces = part.split(':')
    val out = ArrayList<Int>()
    val ok =
        pieces.withIndex().all { (i, piece) ->
            val v4 = if (allowTrailingIpv4 && i == pieces.lastIndex && piece.contains('.')) parseIpv4(piece) else null
            when {
                v4 != null -> {
                    out += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                    out += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                    true
                }
                piece.length in 1..4 && piece.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } -> {
                    out += piece.toInt(16)
                    true
                }
                else -> false
            }
        }
    return out.takeIf { ok }
}
