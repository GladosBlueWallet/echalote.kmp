@file:OptIn(ExperimentalUnsignedTypes::class)

package org.hazae41.echalote

/** Unsigned big-endian integer (minimal, for RSA). */
internal class BigNat private constructor(private val mag: IntArray) {
    fun toFixedBytes(len: Int): ByteArray {
        val out = ByteArray(len)
        var i = mag.size - 1
        var o = len - 1
        while (i >= 0 && o >= 0) {
            val w = mag[i]
            val take = minOf(4, o + 1)
            for (b in 0 until take) {
                out[o] = (w ushr (8 * b)).toByte()
                o--
            }
            i--
        }
        return out
    }

    fun compare(other: BigNat): Int {
        if (mag.size != other.mag.size) return mag.size.compareTo(other.mag.size)
        for (i in mag.indices) {
            val a = mag[i].toLong() and 0xffffffffL
            val b = other.mag[i].toLong() and 0xffffffffL
            if (a != b) return a.compareTo(b)
        }
        return 0
    }

    fun modPow(exp: BigNat, mod: BigNat): BigNat {
        var result = ONE
        var base = this.mod(mod)
        val e = exp.mag
        for (word in e) {
            for (bit in 31 downTo 0) {
                result = result.mul(result).mod(mod)
                if ((word ushr bit) and 1 != 0) {
                    result = result.mul(base).mod(mod)
                }
            }
        }
        // The loop above squares for every bit of every word including leading zeros,
        // which is correct but starts from MSB of the first (possibly shorter) array.
        return result
    }

    fun mod(mod: BigNat): BigNat {
        if (compare(mod) < 0) return this
        return divRem(mod).second
    }

    fun add(other: BigNat): BigNat {
        val a = mag
        val b = other.mag
        val n = maxOf(a.size, b.size)
        val r = IntArray(n + 1)
        var carry = 0L
        for (i in 0 until n) {
            val ai = if (i < a.size) a[a.size - 1 - i].toLong() and 0xffffffffL else 0L
            val bi = if (i < b.size) b[b.size - 1 - i].toLong() and 0xffffffffL else 0L
            val s = ai + bi + carry
            r[n - i] = s.toInt()
            carry = s ushr 32
        }
        r[0] = carry.toInt()
        return fromLimbs(r)
    }

    fun subtract(other: BigNat): BigNat = sub(other)

    fun mul(other: BigNat): BigNat {
        if (isZero() || other.isZero()) return ZERO
        val a = mag
        val b = other.mag
        val r = ULongArray(a.size + b.size)
        for (i in a.indices.reversed()) {
            val ai = a[i].toUInt().toULong()
            var carry = 0UL
            var ri = r.size - (a.size - i)
            for (j in b.indices.reversed()) {
                val bj = b[j].toUInt().toULong()
                val acc = r[ri] + ai * bj + carry
                r[ri] = acc and 0xffffffffUL
                carry = acc shr 32
                ri--
            }
            while (carry != 0UL && ri >= 0) {
                val acc = r[ri] + carry
                r[ri] = acc and 0xffffffffUL
                carry = acc shr 32
                ri--
            }
        }
        val out = IntArray(r.size) { r[it].toInt() }
        return fromLimbs(out)
    }

    private fun divRem(d: BigNat): Pair<BigNat, BigNat> {
        require(!d.isZero()) { "divide by zero" }
        if (compare(d) < 0) return ZERO to this
        var remainder = ZERO
        val quot = IntArray(mag.size)
        for (i in mag.indices) {
            remainder = remainder.shiftLeft32Add(mag[i])
            var q = 0
            // binary search quotient digit 0..2^32-1
            var lo = 0L
            var hi = 0xffffffffL
            while (lo <= hi) {
                val mid = (lo + hi) ushr 1
                val prod = d.mulInt(mid)
                if (prod.compare(remainder) <= 0) {
                    q = mid.toInt()
                    lo = mid + 1
                } else {
                    hi = mid - 1
                }
            }
            if (q != 0) remainder = remainder.sub(d.mulInt(q.toLong() and 0xffffffffL))
            quot[i] = q
        }
        return fromLimbs(quot) to remainder
    }

    private fun mulInt(m: Long): BigNat {
        if (m == 0L) return ZERO
        val mm = m.toULong() and 0xffffffffUL
        val r = ULongArray(mag.size + 1)
        var carry = 0UL
        for (i in mag.indices.reversed()) {
            val acc = mag[i].toUInt().toULong() * mm + carry
            r[i + 1] = acc and 0xffffffffUL
            carry = acc shr 32
        }
        r[0] = carry
        val out = IntArray(r.size) { r[it].toInt() }
        return fromLimbs(out)
    }

    private fun sub(other: BigNat): BigNat {
        val a = mag
        val b = other.mag
        val r = IntArray(a.size)
        var borrow = 0L
        for (i in 0 until a.size) {
            val ai = a[a.size - 1 - i].toLong() and 0xffffffffL
            val bi = if (i < b.size) b[b.size - 1 - i].toLong() and 0xffffffffL else 0L
            var v = ai - bi - borrow
            if (v < 0) {
                v += 1L shl 32
                borrow = 1
            } else {
                borrow = 0
            }
            r[a.size - 1 - i] = v.toInt()
        }
        return fromLimbs(r)
    }

    private fun shiftLeft32Add(word: Int): BigNat {
        if (isZero()) return fromLimbs(intArrayOf(word))
        val r = IntArray(mag.size + 1)
        mag.copyInto(r)
        r[r.size - 1] = word
        return fromLimbs(r)
    }

    private fun isZero(): Boolean = mag.size == 1 && mag[0] == 0

    companion object {
        val ZERO = BigNat(intArrayOf(0))
        val ONE = BigNat(intArrayOf(1))

        fun fromBytes(bytes: ByteArray): BigNat {
            var start = 0
            while (start < bytes.size - 1 && bytes[start].toInt() == 0) start++
            val slice = bytes.copyOfRange(start, bytes.size)
            val limbs = (slice.size + 3) / 4
            val mag = IntArray(limbs)
            var o = slice.size
            for (i in limbs - 1 downTo 0) {
                var w = 0
                val take = minOf(4, o)
                for (b in 0 until take) {
                    w = w or ((slice.u8(o - 1) shl (8 * b)))
                    o--
                }
                mag[i] = w
            }
            return fromLimbs(mag)
        }

        fun fromHex(hex: String): BigNat = fromBytes(hexToBytes(hex))

        private fun fromLimbs(raw: IntArray): BigNat {
            var s = 0
            while (s < raw.size - 1 && raw[s] == 0) s++
            return if (s == 0) BigNat(raw) else BigNat(raw.copyOfRange(s, raw.size))
        }
    }
}

class RsaPublicKey private constructor(
    private val n: BigNat,
    private val e: BigNat,
    private val k: Int,
) {
    fun verifyPkcs1v15Unprefixed(hashed: Memory, signature: Memory): Boolean {
        return try {
            if (signature.bytes.size != k) return false
            val s = BigNat.fromBytes(signature.bytes)
            if (s.compare(n) >= 0) return false
            val m = s.modPow(e, n)
            val em = m.toFixedBytes(k)
            if (em.u8(0) != 0x00 || em.u8(1) != 0x01) return false
            var i = 2
            while (i < em.size && em.u8(i) == 0xff) i++
            if (i < 10 || i >= em.size || em.u8(i) != 0x00) return false
            val digest = em.copyOfRange(i + 1, em.size)
            val want = hashed.bytes
            if (digest.size != want.size) return false
            equalBytes(digest, want)
        } catch (_: Exception) {
            false
        }
    }

    fun verifyPkcs1v15Digest(digestInfoPrefix: ByteArray, hashed: ByteArray, signature: ByteArray): Boolean {
        val want = concatBytes(digestInfoPrefix, hashed)
        return verifyPkcs1v15Unprefixed(Memory(want), Memory(signature))
    }

    companion object {
        val SHA256_DIGESTINFO = hexToBytes("3031300d060960864801650304020105000420")
        val SHA384_DIGESTINFO = hexToBytes("3041300d060960864801650304020205000430")
        val SHA1_DIGESTINFO = hexToBytes("3021300906052b0e03021a05000414")

        fun fromPublicKeyDer(input: Memory): RsaPublicKey {
            val spki = Der.parse(input.bytes)
            val bitString = spki.asSequence()[1]
            val inner = bitString.asBitStringBytes()
            return fromPkcs1Der(Memory(inner))
        }

        fun fromPkcs1Der(input: Memory): RsaPublicKey {
            val seq = Der.parse(input.bytes).asSequence()
            val nBytes = seq[0].asIntegerBytes()
            val eBytes = seq[1].asIntegerBytes()
            val n = BigNat.fromBytes(nBytes)
            val e = BigNat.fromBytes(eBytes)
            val k = nBytes.size
            return RsaPublicKey(n, e, k)
        }
    }
}

object RsaWasm {
    class RsaPublicKey {
        companion object {
            fun from_public_key_der(input: Memory) = org.hazae41.echalote.RsaPublicKey.fromPublicKeyDer(input)
            fun from_pkcs1_der(input: Memory) = org.hazae41.echalote.RsaPublicKey.fromPkcs1Der(input)
        }
    }
    fun initBundled() {}
}

internal class Der(val tag: Int, val body: ByteArray, val raw: ByteArray) {
    fun asSequence(): List<Der> {
        require(tag == 0x30) { "expected SEQUENCE, got $tag" }
        return parseAll(body)
    }

    fun asIntegerBytes(): ByteArray {
        require(tag == 0x02) { "expected INTEGER" }
        var s = 0
        if (body.size > 1 && body[0].toInt() == 0) s = 1
        return body.copyOfRange(s, body.size)
    }

    fun asBitStringBytes(): ByteArray {
        require(tag == 0x03) { "expected BIT STRING" }
        require(body.isNotEmpty()) { "empty BIT STRING" }
        val unused = body.u8(0)
        require(unused == 0) { "unused bits $unused" }
        return body.copyOfRange(1, body.size)
    }

    fun asOctetString(): ByteArray {
        require(tag == 0x04) { "expected OCTET STRING" }
        return body
    }

    fun asOid(): ByteArray {
        require(tag == 0x06) { "expected OID" }
        return body
    }

    companion object {
        fun parse(bytes: ByteArray): Der {
            val (der, rest) = parseOne(bytes, 0)
            if (rest != bytes.size) {
                // allow trailing
            }
            return der
        }

        fun parseAll(bytes: ByteArray): List<Der> {
            val out = ArrayList<Der>()
            var i = 0
            while (i < bytes.size) {
                val (der, next) = parseOne(bytes, i)
                out += der
                i = next
            }
            return out
        }

        fun parseOne(bytes: ByteArray, start: Int): Pair<Der, Int> {
            var i = start
            val tag = bytes.u8(i++)
            var len = bytes.u8(i++)
            if (len and 0x80 != 0) {
                val n = len and 0x7f
                len = 0
                repeat(n) { len = (len shl 8) or bytes.u8(i++) }
            }
            val body = bytes.copyOfRange(i, i + len)
            val raw = bytes.copyOfRange(start, i + len)
            return Der(tag, body, raw) to (i + len)
        }
    }
}
