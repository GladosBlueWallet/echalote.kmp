package io.bluewallet.echalote

private val OID_SUBJECT_ALT_NAME = byteArrayOf(0x55, 0x1d, 0x11)
private const val TAG_EXPLICIT_EXTENSIONS = 0xa3
private const val TAG_SAN_DNS = 0x82
private const val TAG_SAN_IP = 0x87

/**
 * Parses a TLS 1.2 Certificate handshake body (RFC 5246 §7.4.2) into DER certificates,
 * leaf first. Rejects empty chains, empty certificates, length mismatches and chains
 * longer than [MAX_TLS_CHAIN_CERTS].
 */
internal fun parseCertificateChain(body: ByteArray): List<ByteArray> {
    require(body.size >= 3) { "short Certificate" }
    val total = u24(body, 0)
    require(total == body.size - 3) { "Certificate length mismatch" }
    val out = ArrayList<ByteArray>()
    var o = 3
    while (o < body.size) {
        require(o + 3 <= body.size) { "truncated Certificate entry" }
        val len = u24(body, o)
        o += 3
        require(len > 0) { "empty certificate in chain" }
        require(len <= body.size - o) { "certificate overruns Certificate message" }
        require(out.size < MAX_TLS_CHAIN_CERTS) { "certificate chain too long" }
        out += body.copyOfRange(o, o + len)
        o += len
    }
    require(out.isNotEmpty()) { "server sent an empty certificate chain" }
    return out
}

private fun u24(
    b: ByteArray,
    o: Int,
): Int = (b.u8(o) shl 16) or b.u16be(o + 1)

internal class SubjectAltNames(
    val dnsNames: List<String>,
    val ipAddresses: List<ByteArray>,
) {
    /** RFC 6125 / RFC 2818 matching. No subject CN fallback. */
    fun matches(host: String): Boolean {
        val ip = parseIpv4(host)
        return when {
            ip != null -> ipAddresses.any { it.contentEquals(ip) }
            host.contains(':') -> false // IPv6 literals: not supported, fail closed
            else -> dnsNames.any { hostMatchesDnsName(host, it) }
        }
    }
}

/** Extracts dNSName and iPAddress entries from the leaf's subjectAltName extension. */
internal fun subjectAltNames(certDer: ByteArray): SubjectAltNames {
    val tbs = Der.parse(certDer).asSequence()[0].asSequence()
    val extensions = tbs.firstOrNull { it.tag == TAG_EXPLICIT_EXTENSIONS } ?: return SubjectAltNames(emptyList(), emptyList())
    val dns = ArrayList<String>()
    val ips = ArrayList<ByteArray>()
    for (ext in Der.parse(extensions.body).asSequence()) {
        val parts = ext.asSequence()
        if (!parts[0].asOid().contentEquals(OID_SUBJECT_ALT_NAME)) continue
        val names = Der.parse(parts.last().asOctetString()).asSequence()
        for (name in names) {
            when (name.tag) {
                TAG_SAN_DNS -> dns += name.body.decodeToString()
                TAG_SAN_IP -> ips += name.body
            }
        }
    }
    return SubjectAltNames(dns, ips)
}

/** True when the leaf certificate's SANs cover [host]. Malformed certificates never match. */
internal fun certificateMatchesHost(
    leafDer: ByteArray,
    host: String,
): Boolean = runCatching { subjectAltNames(leafDer).matches(host.trimEnd('.')) }.getOrDefault(false)

/**
 * RFC 6125 §6.4 dNSName match: case-insensitive, trailing dot ignored, and a wildcard only
 * as the complete left-most label, covering exactly one label, above at least two labels.
 */
internal fun hostMatchesDnsName(
    host: String,
    pattern: String,
): Boolean {
    val h = host.trimEnd('.').lowercase()
    val p = pattern.trimEnd('.').lowercase()
    return when {
        !isDnsName(h) || p.isEmpty() -> false
        !p.contains('*') -> h == p
        else -> wildcardMatches(h, p)
    }
}

private fun wildcardMatches(
    host: String,
    pattern: String,
): Boolean {
    val suffix = pattern.removePrefix("*.")
    val validPattern =
        pattern.startsWith("*.") && !suffix.contains('*') && suffix.contains('.') && isDnsName(suffix)
    val dot = host.indexOf('.')
    return validPattern && parseIpv4(host) == null && dot > 0 && host.substring(dot + 1) == suffix
}

private fun isDnsName(s: String): Boolean =
    s.isNotEmpty() &&
        s.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 && label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
        }

private fun parseIpv4(host: String): ByteArray? {
    val parts = host.split('.')
    val octets =
        parts.mapNotNull { part ->
            part.takeIf { it.length in 1..3 && it.all { c -> c in '0'..'9' } }?.toInt()?.takeIf { it <= 255 }
        }
    return if (parts.size == 4 && octets.size == 4) ByteArray(4) { i -> octets[i].toByte() } else null
}

/** Digest and DigestInfo prefix for the ServerKeyExchange signature; only offered hashes. */
internal fun serverKeyExchangeDigest(
    sigHash: Int,
    signed: ByteArray,
): Pair<ByteArray, ByteArray> =
    when (sigHash) {
        4 -> Sha256.hash(signed) to RsaPublicKey.SHA256_DIGESTINFO
        5 -> Sha384.hash(signed) to RsaPublicKey.SHA384_DIGESTINFO
        else -> throw IllegalArgumentException("unsupported TLS signature hash $sigHash")
    }
