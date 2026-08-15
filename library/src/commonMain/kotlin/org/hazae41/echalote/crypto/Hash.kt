package org.hazae41.echalote

internal object Sha1 {
    fun hash(data: ByteArray): ByteArray = Hasher().update(data).finalize()

    class Hasher() {
        private var h0 = 0x67452301
        private var h1 = 0xEFCDAB89.toInt()
        private var h2 = 0x98BADCFE.toInt()
        private var h3 = 0x10325476
        private var h4 = 0xC3D2E1F0.toInt()
        private val block = ByteArray(64)
        private var blockOff = 0
        private var total = 0L

        constructor(other: Hasher) : this() {
            h0 = other.h0; h1 = other.h1; h2 = other.h2; h3 = other.h3; h4 = other.h4
            other.block.copyInto(block)
            blockOff = other.blockOff
            total = other.total
        }

        fun clone(): Hasher = Hasher(this)

        fun update(data: ByteArray, off: Int = 0, len: Int = data.size - off): Hasher {
            var i = off
            val end = off + len
            total += len
            while (i < end) {
                val n = minOf(64 - blockOff, end - i)
                data.copyInto(block, blockOff, i, i + n)
                blockOff += n
                i += n
                if (blockOff == 64) {
                    compress()
                    blockOff = 0
                }
            }
            return this
        }

        fun finalize(): ByteArray {
            val copy = clone()
            val bitLen = copy.total * 8
            copy.update(byteArrayOf(0x80.toByte()))
            val zeros = ((56 - (copy.total % 64)) + 64) % 64
            if (zeros != 0L) copy.update(ByteArray(zeros.toInt()))
            val len = ByteArray(8)
            len.putU64be(0, bitLen)
            copy.update(len)
            val out = ByteArray(20)
            fun put(word: Int, at: Int) {
                out.putU32be(at, word)
            }
            put(copy.h0, 0); put(copy.h1, 4); put(copy.h2, 8); put(copy.h3, 12); put(copy.h4, 16)
            return out
        }

        private fun compress() {
            val w = IntArray(80)
            for (i in 0 until 16) w[i] = block.u32be(i * 4)
            for (i in 16 until 80) {
                w[i] = (w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]).rotateLeft(1)
            }
            var a = h0; var b = h1; var c = h2; var d = h3; var e = h4
            for (i in 0 until 80) {
                val (f, k) = when {
                    i < 20 -> ((b and c) or (b.inv() and d)) to 0x5A827999
                    i < 40 -> (b xor c xor d) to 0x6ED9EBA1
                    i < 60 -> ((b and c) or (b and d) or (c and d)) to 0x8F1BBCDC.toInt()
                    else -> (b xor c xor d) to 0xCA62C1D6.toInt()
                }
                val temp = a.rotateLeft(5) + f + e + k + w[i]
                e = d; d = c; c = b.rotateLeft(30); b = a; a = temp
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e
        }
    }
}

internal object Sha256 {
    private val K = intArrayOf(
        0x428a2f98, 0x71374491, 0xb5c0fbcf.toInt(), 0xe9b5dba5.toInt(),
        0x3956c25b, 0x59f111f1, 0x923f82a4.toInt(), 0xab1c5ed5.toInt(),
        0xd807aa98.toInt(), 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe.toInt(), 0x9bdc06a7.toInt(), 0xc19bf174.toInt(),
        0xe49b69c1.toInt(), 0xefbe4786.toInt(), 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152.toInt(), 0xa831c66d.toInt(), 0xb00327c8.toInt(), 0xbf597fc7.toInt(),
        0xc6e00bf3.toInt(), 0xd5a79147.toInt(), 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e.toInt(), 0x92722c85.toInt(),
        0xa2bfe8a1.toInt(), 0xa81a664b.toInt(), 0xc24b8b70.toInt(), 0xc76c51a3.toInt(),
        0xd192e819.toInt(), 0xd6990624.toInt(), 0xf40e3585.toInt(), 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814.toInt(), 0x8cc70208.toInt(),
        0x90befffa.toInt(), 0xa4506ceb.toInt(), 0xbef9a3f7.toInt(), 0xc67178f2.toInt(),
    )

    fun hash(data: ByteArray): ByteArray {
        var h0 = 0x6a09e667
        var h1 = 0xbb67ae85.toInt()
        var h2 = 0x3c6ef372
        var h3 = 0xa54ff53a.toInt()
        var h4 = 0x510e527f
        var h5 = 0x9b05688c.toInt()
        var h6 = 0x1f83d9ab
        var h7 = 0x5be0cd19
        val bitLen = data.size.toLong() * 8
        val paddedLen = ((data.size + 9 + 63) / 64) * 64
        val padded = ByteArray(paddedLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        padded.putU64be(paddedLen - 8, bitLen)
        val w = IntArray(64)
        var offset = 0
        while (offset < paddedLen) {
            for (i in 0 until 16) w[i] = padded.u32be(offset + i * 4)
            for (i in 16 until 64) {
                val s0 = w[i - 15].rotateRight(7) xor w[i - 15].rotateRight(18) xor (w[i - 15] ushr 3)
                val s1 = w[i - 2].rotateRight(17) xor w[i - 2].rotateRight(19) xor (w[i - 2] ushr 10)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }
            var a = h0; var b = h1; var c = h2; var d = h3
            var e = h4; var f = h5; var g = h6; var h = h7
            for (i in 0 until 64) {
                val s1 = e.rotateRight(6) xor e.rotateRight(11) xor e.rotateRight(25)
                val ch = (e and f) xor (e.inv() and g)
                val t1 = h + s1 + ch + K[i] + w[i]
                val s0 = a.rotateRight(2) xor a.rotateRight(13) xor a.rotateRight(22)
                val maj = (a and b) xor (a and c) xor (b and c)
                val t2 = s0 + maj
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h
            offset += 64
        }
        val out = ByteArray(32)
        out.putU32be(0, h0); out.putU32be(4, h1); out.putU32be(8, h2); out.putU32be(12, h3)
        out.putU32be(16, h4); out.putU32be(20, h5); out.putU32be(24, h6); out.putU32be(28, h7)
        return out
    }
}

internal object Sha384 {
    fun hash(data: ByteArray): ByteArray = Sha512.hash(data, bits384 = true)
}

internal object Sha512 {
    private val K = longArrayOf(
        0x428a2f98d728ae22UL.toLong(), 0x7137449123ef65cdUL.toLong(), 0xb5c0fbcfec4d3b2fUL.toLong(), 0xe9b5dba58189dbbcUL.toLong(),
        0x3956c25bf348b538UL.toLong(), 0x59f111f1b605d019UL.toLong(), 0x923f82a4af194f9bUL.toLong(), 0xab1c5ed5da6d8118UL.toLong(),
        0xd807aa98a3030242UL.toLong(), 0x12835b0145706fbeUL.toLong(), 0x243185be4ee4b28cUL.toLong(), 0x550c7dc3d5ffb4e2UL.toLong(),
        0x72be5d74f27b896fUL.toLong(), 0x80deb1fe3b1696b1UL.toLong(), 0x9bdc06a725c71235UL.toLong(), 0xc19bf174cf692694UL.toLong(),
        0xe49b69c19ef14ad2UL.toLong(), 0xefbe4786384f25e3UL.toLong(), 0x0fc19dc68b8cd5b5UL.toLong(), 0x240ca1cc77ac9c65UL.toLong(),
        0x2de92c6f592b0275UL.toLong(), 0x4a7484aa6ea6e483UL.toLong(), 0x5cb0a9dcbd41fbd4UL.toLong(), 0x76f988da831153b5UL.toLong(),
        0x983e5152ee66dfabUL.toLong(), 0xa831c66d2db43210UL.toLong(), 0xb00327c898fb213fUL.toLong(), 0xbf597fc7beef0ee4UL.toLong(),
        0xc6e00bf33da88fc2UL.toLong(), 0xd5a79147930aa725UL.toLong(), 0x06ca6351e003826fUL.toLong(), 0x142929670a0e6e70UL.toLong(),
        0x27b70a8546d22ffcUL.toLong(), 0x2e1b21385c26c926UL.toLong(), 0x4d2c6dfc5ac42aedUL.toLong(), 0x53380d139d95b3dfUL.toLong(),
        0x650a73548baf63deUL.toLong(), 0x766a0abb3c77b2a8UL.toLong(), 0x81c2c92e47edaee6UL.toLong(), 0x92722c851482353bUL.toLong(),
        0xa2bfe8a14cf10364UL.toLong(), 0xa81a664bbc423001UL.toLong(), 0xc24b8b70d0f89791UL.toLong(), 0xc76c51a30654be30UL.toLong(),
        0xd192e819d6ef5218UL.toLong(), 0xd69906245565a910UL.toLong(), 0xf40e35855771202aUL.toLong(), 0x106aa07032bbd1b8UL.toLong(),
        0x19a4c116b8d2d0c8UL.toLong(), 0x1e376c085141ab53UL.toLong(), 0x2748774cdf8eeb99UL.toLong(), 0x34b0bcb5e19b48a8UL.toLong(),
        0x391c0cb3c5c95a63UL.toLong(), 0x4ed8aa4ae3418acbUL.toLong(), 0x5b9cca4f7763e373UL.toLong(), 0x682e6ff3d6b2b8a3UL.toLong(),
        0x748f82ee5defb2fcUL.toLong(), 0x78a5636f43172f60UL.toLong(), 0x84c87814a1f0ab72UL.toLong(), 0x8cc702081a6439ecUL.toLong(),
        0x90befffa23631e28UL.toLong(), 0xa4506cebde82bde9UL.toLong(), 0xbef9a3f7b2c67915UL.toLong(), 0xc67178f2e372532bUL.toLong(),
        0xca273eceea26619cUL.toLong(), 0xd186b8c721c0c207UL.toLong(), 0xeada7dd6cde0eb1eUL.toLong(), 0xf57d4f7fee6ed178UL.toLong(),
        0x06f067aa72176fbaUL.toLong(), 0x0a637dc5a2c898a6UL.toLong(), 0x113f9804bef90daeUL.toLong(), 0x1b710b35131c471bUL.toLong(),
        0x28db77f523047d84UL.toLong(), 0x32caab7b40c72493UL.toLong(), 0x3c9ebe0a15c9bebcUL.toLong(), 0x431d67c49c100d4cUL.toLong(),
        0x4cc5d4becb3e42b6UL.toLong(), 0x597f299cfc657e2aUL.toLong(), 0x5fcb6fab3ad6faecUL.toLong(), 0x6c44198c4a475817UL.toLong(),
    )

    fun hash(data: ByteArray, bits384: Boolean = false): ByteArray {
        var h0 = if (bits384) 0xcbbb9d5dc1059ed8UL.toLong() else 0x6a09e667f3bcc908UL.toLong()
        var h1 = if (bits384) 0x629a292a367cd507UL.toLong() else 0xbb67ae8584caa73bUL.toLong()
        var h2 = if (bits384) 0x9159015a3070dd17UL.toLong() else 0x3c6ef372fe94f82bUL.toLong()
        var h3 = if (bits384) 0x152fecd8f70e5939UL.toLong() else 0xa54ff53a5f1d36f1UL.toLong()
        var h4 = if (bits384) 0x67332667ffc00b31UL.toLong() else 0x510e527fade682d1UL.toLong()
        var h5 = if (bits384) 0x8eb44a8768581511UL.toLong() else 0x9b05688c2b3e6c1fUL.toLong()
        var h6 = if (bits384) 0xdb0c2e0d64f98fa7UL.toLong() else 0x1f83d9abfb41bd6bUL.toLong()
        var h7 = if (bits384) 0x47b5481dbefa4fa4UL.toLong() else 0x5be0cd19137e2179UL.toLong()
        val bitLen = data.size.toLong() * 8
        val paddedLen = ((data.size + 17 + 127) / 128) * 128
        val padded = ByteArray(paddedLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()
        padded.putU64be(paddedLen - 8, bitLen)
        val w = LongArray(80)
        var offset = 0
        while (offset < paddedLen) {
            for (i in 0 until 16) {
                var v = 0L
                for (b in 0 until 8) v = (v shl 8) or padded.u8(offset + i * 8 + b).toLong()
                w[i] = v
            }
            for (i in 16 until 80) {
                val s0 = w[i - 15].rotateRight(1) xor w[i - 15].rotateRight(8) xor (w[i - 15] ushr 7)
                val s1 = w[i - 2].rotateRight(19) xor w[i - 2].rotateRight(61) xor (w[i - 2] ushr 6)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }
            var a = h0; var b = h1; var c = h2; var d = h3
            var e = h4; var f = h5; var g = h6; var h = h7
            for (i in 0 until 80) {
                val s1 = e.rotateRight(14) xor e.rotateRight(18) xor e.rotateRight(41)
                val ch = (e and f) xor (e.inv() and g)
                val t1 = h + s1 + ch + K[i] + w[i]
                val s0 = a.rotateRight(28) xor a.rotateRight(34) xor a.rotateRight(39)
                val maj = (a and b) xor (a and c) xor (b and c)
                val t2 = s0 + maj
                h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
            }
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e; h5 += f; h6 += g; h7 += h
            offset += 128
        }
        val words = if (bits384) 6 else 8
        val out = ByteArray(words * 8)
        val hs = longArrayOf(h0, h1, h2, h3, h4, h5, h6, h7)
        for (i in 0 until words) {
            var v = hs[i]
            for (b in 7 downTo 0) {
                out[i * 8 + b] = v.toByte()
                v = v ushr 8
            }
        }
        return out
    }
}

internal fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = hmac(key, data, 64, Sha256::hash)
internal fun hmacSha384(key: ByteArray, data: ByteArray): ByteArray = hmac(key, data, 128, Sha384::hash)

private fun hmac(key: ByteArray, data: ByteArray, block: Int, hash: (ByteArray) -> ByteArray): ByteArray {
    var k = if (key.size > block) hash(key) else key
    if (k.size < block) k = k.copyOf(block)
    val ipad = ByteArray(block)
    val opad = ByteArray(block)
    for (i in 0 until block) {
        ipad[i] = (k[i].toInt() xor 0x36).toByte()
        opad[i] = (k[i].toInt() xor 0x5c).toByte()
    }
    return hash(concatBytes(opad, hash(concatBytes(ipad, data))))
}

internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    val prk = hmacSha256(salt, ikm)
    val n = (length + 31) / 32
    val okm = ByteArray(n * 32)
    var prev = ByteArray(0)
    for (i in 1..n) {
        prev = hmacSha256(prk, concatBytes(prev, info, byteArrayOf(i.toByte())))
        prev.copyInto(okm, (i - 1) * 32)
    }
    return okm.copyOf(length)
}

internal fun tlsPrfSha384(secret: ByteArray, label: String, seed: ByteArray, length: Int): ByteArray {
    val labelBytes = utf8Bytes(label)
    val fullSeed = concatBytes(labelBytes, seed)
    val out = ByteArray(length)
    var a = hmacSha384(secret, fullSeed)
    var filled = 0
    while (filled < length) {
        val block = hmacSha384(secret, concatBytes(a, fullSeed))
        val n = minOf(block.size, length - filled)
        block.copyInto(out, filled, 0, n)
        filled += n
        a = hmacSha384(secret, a)
    }
    return out
}
