package org.hazae41.echalote

internal expect fun fillSecureRandom(bytes: ByteArray)

internal expect fun currentEpochMillis(): Long

fun secureRandom(n: Int): ByteArray {
    val out = ByteArray(n)
    fillSecureRandom(out)
    return out
}

fun randomUuid(): String {
    val b = secureRandom(16)
    b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
    b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
    val h = bytesToHex(b)
    return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
}
