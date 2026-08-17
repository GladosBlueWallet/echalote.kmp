package io.bluewallet.echalote

/** AES-GCM (NIST SP 800-38D) with 12-byte IV. */
internal object AesGcm {
    fun encrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        require(iv.size == 12) { "GCM IV must be 12 bytes" }
        val roundKeys = Aes.expandKey(key)
        val h = ByteArray(16)
        Aes.encryptBlock(roundKeys, ByteArray(16), 0, h, 0)
        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1
        val ctr = j0.copyOf()
        inc32(ctr)
        val ciphertext = ByteArray(plaintext.size)
        ctrXor(roundKeys, ctr, plaintext, ciphertext)
        val s = ghash(h, aad, ciphertext)
        val tag = ByteArray(16)
        Aes.encryptBlock(roundKeys, j0, 0, tag, 0)
        xor16(tag, s)
        return ciphertext to tag
    }

    fun decrypt(key: ByteArray, iv: ByteArray, aad: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray {
        require(iv.size == 12) { "GCM IV must be 12 bytes" }
        require(tag.size == 16) { "GCM tag must be 16 bytes" }
        val roundKeys = Aes.expandKey(key)
        val h = ByteArray(16)
        Aes.encryptBlock(roundKeys, ByteArray(16), 0, h, 0)
        val j0 = ByteArray(16)
        iv.copyInto(j0, 0, 0, 12)
        j0[15] = 1
        val s = ghash(h, aad, ciphertext)
        val expect = ByteArray(16)
        Aes.encryptBlock(roundKeys, j0, 0, expect, 0)
        xor16(expect, s)
        require(equalBytes(expect, tag)) { "GCM authentication failed" }
        val ctr = j0.copyOf()
        inc32(ctr)
        val plaintext = ByteArray(ciphertext.size)
        ctrXor(roundKeys, ctr, ciphertext, plaintext)
        return plaintext
    }

    private fun ctrXor(roundKeys: IntArray, counter: ByteArray, input: ByteArray, output: ByteArray) {
        val block = ByteArray(16)
        var i = 0
        while (i < input.size) {
            Aes.encryptBlock(roundKeys, counter, 0, block, 0)
            inc32(counter)
            val n = minOf(16, input.size - i)
            for (j in 0 until n) {
                output[i + j] = (input[i + j].toInt() xor block[j].toInt()).toByte()
            }
            i += n
        }
    }

    private fun inc32(block: ByteArray) {
        for (i in 15 downTo 12) {
            val v = (block[i].toInt() + 1) and 0xff
            block[i] = v.toByte()
            if (v != 0) break
        }
    }

    private fun ghash(h: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        var x = ByteArray(16)
        x = ghashBlocks(x, h, aad)
        x = ghashBlocks(x, h, ciphertext)
        val len = ByteArray(16)
        putU64be(len, 0, aad.size.toLong() * 8)
        putU64be(len, 8, ciphertext.size.toLong() * 8)
        xor16(x, len)
        return gmult(x, h)
    }

    private fun ghashBlocks(start: ByteArray, h: ByteArray, data: ByteArray): ByteArray {
        var x = start
        var i = 0
        while (i < data.size) {
            val block = ByteArray(16)
            val n = minOf(16, data.size - i)
            data.copyInto(block, 0, i, i + n)
            xor16(x, block)
            x = gmult(x, h)
            i += 16
        }
        return x
    }

    private fun gmult(x: ByteArray, y: ByteArray): ByteArray {
        val z = ByteArray(16)
        val v = y.copyOf()
        for (i in 0 until 16) {
            val xi = x.u8(i)
            for (j in 7 downTo 0) {
                if ((xi ushr j) and 1 == 1) xor16(z, v)
                val lsb = v[15].toInt() and 1
                var carry = 0
                for (k in 0 until 16) {
                    val b = v.u8(k)
                    v[k] = ((b ushr 1) or (carry shl 7)).toByte()
                    carry = b and 1
                }
                if (lsb != 0) v[0] = (v.u8(0) xor 0xe1).toByte()
            }
        }
        return z
    }

    private fun xor16(a: ByteArray, b: ByteArray) {
        for (i in 0 until 16) a[i] = (a[i].toInt() xor b[i].toInt()).toByte()
    }

    private fun putU64be(out: ByteArray, i: Int, v: Long) {
        out.putU64be(i, v)
    }
}
