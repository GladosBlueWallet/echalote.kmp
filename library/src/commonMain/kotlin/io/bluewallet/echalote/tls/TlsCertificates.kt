package io.bluewallet.echalote

private val OID_SUBJECT_ALT_NAME = byteArrayOf(0x55, 0x1d, 0x11)
private const val TAG_EXPLICIT_EXTENSIONS = 0xa3
private const val TAG_SAN_DNS = 0x82
private const val TAG_SAN_IP = 0x87
private const val TAG_BOOLEAN = 0x01

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
    /**
     * RFC 6125 / RFC 2818 matching. No subject CN fallback. An IP literal (IPv4 dotted quad, or
     * IPv6 with or without brackets) is compared byte-for-byte with the iPAddress SANs only.
     * Anything numeric that is not a canonical IPv4 address (leading zeros, fewer than four parts,
     * an all-digit last label) matches nothing, because resolvers disagree on what it means.
     */
    fun matches(host: String): Boolean {
        val ip = parseIpLiteral(host)
        return when {
            ip != null -> ipAddresses.any { it.contentEquals(ip) }
            host.contains(':') || host.startsWith('[') -> false
            looksNumeric(host) -> false
            else -> dnsNames.any { dnsNameMatches(host, it) }
        }
    }
}

/**
 * extnValue of a subjectAltName Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
 * extnValue OCTET STRING }, or null for any other extension. Any other shape is rejected.
 */
private fun extensionValue(parts: List<Der>): ByteArray? {
    require(parts.size in 2..3) { "malformed certificate extension" }
    if (!parts[0].asOid().contentEquals(OID_SUBJECT_ALT_NAME)) return null
    require(parts.size == 2 || parts[1].tag == TAG_BOOLEAN) { "malformed subjectAltName extension" }
    return parts.last().asOctetString()
}

/** Extracts dNSName and iPAddress entries from the leaf's subjectAltName extension. */
internal fun subjectAltNames(certDer: ByteArray): SubjectAltNames {
    val tbs = Der.parse(certDer).asSequence()[0].asSequence()
    val extensions = tbs.firstOrNull { it.tag == TAG_EXPLICIT_EXTENSIONS } ?: return SubjectAltNames(emptyList(), emptyList())
    val dns = ArrayList<String>()
    val ips = ArrayList<ByteArray>()
    var seen = false
    for (ext in Der.parse(extensions.body).asSequence()) {
        val value = extensionValue(ext.asSequence()) ?: continue
        require(!seen) { "duplicate subjectAltName extension" } // RFC 5280 §4.2
        seen = true
        for (name in Der.parse(value).asSequence()) {
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
): Boolean = runCatching { subjectAltNames(leafDer).matches(host.removeSuffix(".")) }.getOrDefault(false)

/**
 * RFC 6125 §6.4 dNSName match: case-insensitive, one trailing (root) dot ignored, and a wildcard only
 * as the complete left-most label, covering exactly one label, above at least two labels.
 */
internal fun hostMatchesDnsName(
    host: String,
    pattern: String,
): Boolean = dnsNameMatches(host.removeSuffix("."), pattern)

/** [host] already has its single root dot removed; a second one is an empty label and fails. */
private fun dnsNameMatches(
    host: String,
    pattern: String,
): Boolean {
    val h = host.lowercase()
    val p = pattern.removeSuffix(".").lowercase()
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
    return validPattern && !looksNumeric(host) && dot > 0 && host.substring(dot + 1) == suffix
}

private fun isDnsName(s: String): Boolean =
    s.isNotEmpty() &&
        s.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 && label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
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
