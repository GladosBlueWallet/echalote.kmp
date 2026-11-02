package io.bluewallet.echalote

internal actual fun platformRsaPublicOp(
    signature: ByteArray,
    exponent: ByteArray,
    modulus: ByteArray,
    outLen: Int,
): ByteArray? = null

internal actual fun platformP256Ecdh(peerUncompressed: ByteArray): Pair<ByteArray, ByteArray>? = null
