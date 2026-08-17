package io.bluewallet.echalote

/**
 * AES block cipher (128/256) plus CTR with mid-block offset.
 * CTR matches `@hazae41/aes.wasm` / noble: 16-byte big-endian counter, leftover keystream.
 */
internal object Aes {
    private val SBOX = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    )
    private val RCON = intArrayOf(0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)

    private fun xtime(a: Int): Int {
        val x = (a shl 1) and 0xff
        return if ((a and 0x80) != 0) x xor 0x1b else x
    }

    private fun mul(a: Int, b: Int): Int {
        var aa = a
        var bb = b
        var p = 0
        for (i in 0 until 8) {
            if ((bb and 1) != 0) p = p xor aa
            aa = xtime(aa)
            bb = bb ushr 1
        }
        return p and 0xff
    }

    fun expandKey(key: ByteArray): IntArray {
        val nk = when (key.size) {
            16 -> 4
            32 -> 8
            else -> throw IllegalArgumentException("AES key must be 16 or 32 bytes")
        }
        val nr = nk + 6
        val w = IntArray(4 * (nr + 1))
        for (i in 0 until nk) {
            w[i] = key.u32be(4 * i)
        }
        for (i in nk until w.size) {
            var temp = w[i - 1]
            if (i % nk == 0) {
                temp = subWord(rotWord(temp)) xor (RCON[i / nk] shl 24)
            } else if (nk > 6 && i % nk == 4) {
                temp = subWord(temp)
            }
            w[i] = w[i - nk] xor temp
        }
        return w
    }

    private fun subWord(w: Int): Int =
        (SBOX[(w ushr 24) and 0xff] shl 24) or
            (SBOX[(w ushr 16) and 0xff] shl 16) or
            (SBOX[(w ushr 8) and 0xff] shl 8) or
            SBOX[w and 0xff]

    private fun rotWord(w: Int): Int = (w shl 8) or (w ushr 24)

    fun encryptBlock(roundKeys: IntArray, input: ByteArray, inOff: Int, output: ByteArray, outOff: Int) {
        val nr = roundKeys.size / 4 - 1
        val s = IntArray(16)
        for (i in 0 until 16) s[i] = input.u8(inOff + i)
        addRoundKey(s, roundKeys, 0)
        for (round in 1 until nr) {
            subBytes(s)
            shiftRows(s)
            mixColumns(s)
            addRoundKey(s, roundKeys, round)
        }
        subBytes(s)
        shiftRows(s)
        addRoundKey(s, roundKeys, nr)
        for (i in 0 until 16) output[outOff + i] = s[i].toByte()
    }

    private fun subBytes(s: IntArray) {
        for (i in 0 until 16) s[i] = SBOX[s[i]]
    }

    private fun shiftRows(s: IntArray) {
        var t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t
        t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t
        t = s[3]; s[3] = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = t
    }

    private fun mixColumns(s: IntArray) {
        for (c in 0 until 4) {
            val i = 4 * c
            val a0 = s[i]; val a1 = s[i + 1]; val a2 = s[i + 2]; val a3 = s[i + 3]
            s[i] = mul(a0, 2) xor mul(a1, 3) xor a2 xor a3
            s[i + 1] = a0 xor mul(a1, 2) xor mul(a2, 3) xor a3
            s[i + 2] = a0 xor a1 xor mul(a2, 2) xor mul(a3, 3)
            s[i + 3] = mul(a0, 3) xor a1 xor a2 xor mul(a3, 2)
        }
    }

    private fun addRoundKey(s: IntArray, w: IntArray, round: Int) {
        for (c in 0 until 4) {
            val k = w[round * 4 + c]
            s[4 * c] = s[4 * c] xor ((k ushr 24) and 0xff)
            s[4 * c + 1] = s[4 * c + 1] xor ((k ushr 16) and 0xff)
            s[4 * c + 2] = s[4 * c + 2] xor ((k ushr 8) and 0xff)
            s[4 * c + 3] = s[4 * c + 3] xor (k and 0xff)
        }
    }
}

class Memory(val bytes: ByteArray) {
    fun len(): Int = bytes.size
}

object AesWasm {
    fun initBundled() {}
}

class Aes128Ctr128BEKey(key: Memory, iv: Memory) {
    private val roundKeys = Aes.expandKey(key.bytes.copyOf())
    private val counter = iv.bytes.copyOf()
    private val keystream = ByteArray(16)
    private var offset = 16

    fun applyKeystream(memory: Memory) {
        val bytes = memory.bytes
        var i = 0
        while (i < bytes.size) {
            if (offset >= 16) {
                Aes.encryptBlock(roundKeys, counter, 0, keystream, 0)
                incrementBe(counter)
                offset = 0
            }
            val n = minOf(16 - offset, bytes.size - i)
            for (j in 0 until n) {
                bytes[i + j] = (bytes[i + j].toInt() xor keystream[offset + j].toInt()).toByte()
            }
            i += n
            offset += n
        }
    }

    private fun incrementBe(counter: ByteArray) {
        for (i in counter.size - 1 downTo 0) {
            val v = (counter[i].toInt() + 1) and 0xff
            counter[i] = v.toByte()
            if (v != 0) break
        }
    }
}
