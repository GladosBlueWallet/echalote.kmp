package io.bluewallet.echalote

object Base64 {
    private val ENC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray()
    private val DEC = IntArray(256) { -1 }.also { table ->
        ENC.forEachIndexed { i, c -> table[c.code] = i }
        table['-'.code] = 62
        table['_'.code] = 63
    }

    fun encode(bytes: ByteArray, padded: Boolean = true): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i + 2 < bytes.size) {
            val n = (bytes.u8(i) shl 16) or (bytes.u8(i + 1) shl 8) or bytes.u8(i + 2)
            out.append(ENC[(n ushr 18) and 63])
            out.append(ENC[(n ushr 12) and 63])
            out.append(ENC[(n ushr 6) and 63])
            out.append(ENC[n and 63])
            i += 3
        }
        val rem = bytes.size - i
        if (rem == 1) {
            val n = bytes.u8(i) shl 16
            out.append(ENC[(n ushr 18) and 63])
            out.append(ENC[(n ushr 12) and 63])
            if (padded) out.append("==")
        } else if (rem == 2) {
            val n = (bytes.u8(i) shl 16) or (bytes.u8(i + 1) shl 8)
            out.append(ENC[(n ushr 18) and 63])
            out.append(ENC[(n ushr 12) and 63])
            out.append(ENC[(n ushr 6) and 63])
            if (padded) out.append('=')
        }
        return out.toString()
    }

    fun encodeUnpadded(bytes: ByteArray): String = encode(bytes, padded = false)

    fun decode(text: String): ByteArray {
        val clean = buildString(text.length) {
            for (c in text) {
                if (c != '=' && c != '\n' && c != '\r' && c != ' ') append(c)
            }
        }
        val pad = (4 - (clean.length % 4)) % 4
        val s = clean + "=".repeat(pad)
        val out = ByteArray(s.length / 4 * 3)
        var o = 0
        var i = 0
        while (i < s.length) {
            val a = DEC[s[i].code]
            val b = DEC[s[i + 1].code]
            val c = if (s[i + 2] == '=') 0 else DEC[s[i + 2].code]
            val d = if (s[i + 3] == '=') 0 else DEC[s[i + 3].code]
            if (a < 0 || b < 0 || (s[i + 2] != '=' && c < 0) || (s[i + 3] != '=' && d < 0)) {
                throw IllegalArgumentException("invalid base64")
            }
            val n = (a shl 18) or (b shl 12) or (c shl 6) or d
            out[o++] = (n ushr 16).toByte()
            if (s[i + 2] != '=') out[o++] = (n ushr 8).toByte()
            if (s[i + 3] != '=') out[o++] = n.toByte()
            i += 4
        }
        return if (o == out.size) out else out.copyOf(o)
    }
}
