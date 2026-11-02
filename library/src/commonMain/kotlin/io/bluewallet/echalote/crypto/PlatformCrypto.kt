package io.bluewallet.echalote

/**
 * RSA public-key operation `signature^exponent mod modulus` (big-endian, unsigned) using the
 * platform's big integers, returned as [outLen] bytes; null when the platform has none, so the
 * caller falls back to the pure-Kotlin [BigNat] (much slower: ~10-35 ms per verify on the JVM).
 */
internal expect fun platformRsaPublicOp(
    signature: ByteArray,
    exponent: ByteArray,
    modulus: ByteArray,
    outLen: Int,
): ByteArray?

/**
 * Ephemeral ECDH on P-256 with the platform provider: makes a fresh key pair, agrees with
 * [peerUncompressed] (already checked to be on the curve) and returns
 * (our uncompressed public point, shared x coordinate). Null when the platform has no provider,
 * so the caller falls back to the pure-Kotlin [P256].
 */
internal expect fun platformP256Ecdh(peerUncompressed: ByteArray): Pair<ByteArray, ByteArray>?

/** Big-endian two's-complement (e.g. java BigInteger.toByteArray) to exactly [len] unsigned bytes. */
internal fun unsignedFixed(
    raw: ByteArray,
    len: Int,
): ByteArray {
    var start = 0
    while (start < raw.size - 1 && raw[start] == 0.toByte()) start++
    val n = raw.size - start
    require(n <= len) { "value longer than $len bytes" }
    val out = ByteArray(len)
    raw.copyInto(out, len - n, start, raw.size)
    return out
}
