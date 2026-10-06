package io.bluewallet.echalote

import java.io.ByteArrayOutputStream
import java.util.zip.Inflater

internal actual fun inflateZlibOrNull(input: ByteArray): ByteArray? {
    if (input.size < 2 || (input[0].toInt() and 0xff) != 0x78) return null
    val inf = Inflater()
    return try {
        inf.setInput(input)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (!inf.finished()) {
            val n = inf.inflate(buf)
            if (n == 0) {
                if (inf.needsInput() || inf.needsDictionary()) return null
            } else {
                if (out.size() + n > MAX_HTTP1_BODY) return null
                out.write(buf, 0, n)
            }
        }
        if (inf.remaining > 0 && !inf.finished()) return null
        out.toByteArray()
    } catch (_: Exception) {
        null
    } finally {
        inf.end()
    }
}
