package org.hazae41.echalote

fun concatBytes(vararg parts: ByteArray): ByteArray {
    var len = 0
    for (p in parts) len += p.size
    val out = ByteArray(len)
    var offset = 0
    for (p in parts) {
        p.copyInto(out, offset)
        offset += p.size
    }
    return out
}

fun equalBytes(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}

fun hexToBytes(hex: String): ByteArray {
    val s = hex.trim()
    if (s.length % 2 != 0) throw IllegalArgumentException("odd hex length: ${s.length}")
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        out[i] = s.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
    return out
}

fun bytesToHex(bytes: ByteArray): String {
    val chars = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xff
        chars[i * 2] = HEX_DIGITS[v ushr 4]
        chars[i * 2 + 1] = HEX_DIGITS[v and 0x0f]
    }
    return chars.concatToString()
}

fun utf8Bytes(s: String): ByteArray = s.encodeToByteArray()

fun bytesToUtf8(bytes: ByteArray): String = bytes.decodeToString()

internal fun ByteArray.u8(i: Int): Int = this[i].toInt() and 0xff

internal fun ByteArray.u16be(i: Int): Int = (u8(i) shl 8) or u8(i + 1)

internal fun ByteArray.u32be(i: Int): Int =
    (u8(i) shl 24) or (u8(i + 1) shl 16) or (u8(i + 2) shl 8) or u8(i + 3)

internal fun ByteArray.putU8(i: Int, v: Int) {
    this[i] = v.toByte()
}

internal fun ByteArray.putU16be(i: Int, v: Int) {
    this[i] = (v ushr 8).toByte()
    this[i + 1] = v.toByte()
}

internal fun ByteArray.putU32be(i: Int, v: Int) {
    this[i] = (v ushr 24).toByte()
    this[i + 1] = (v ushr 16).toByte()
    this[i + 2] = (v ushr 8).toByte()
    this[i + 3] = v.toByte()
}

internal fun ByteArray.putU64be(i: Int, v: Long) {
    for (b in 0 until 8) {
        this[i + b] = (v ushr (56 - 8 * b)).toByte()
    }
}

private val HEX_DIGITS = charArrayOf(
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
)
