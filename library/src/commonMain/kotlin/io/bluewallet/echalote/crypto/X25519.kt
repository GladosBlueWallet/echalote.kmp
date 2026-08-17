package io.bluewallet.echalote

/**
 * Curve25519 field + X25519, ported from public-domain TweetNaCl (16×16-bit limbs).
 */
internal class Gf(val n: LongArray = LongArray(16)) {
    fun copy(): Gf = Gf(n.copyOf())
}

internal fun gfCar(o: LongArray) {
    var c = 1L
    for (i in 0 until 16) {
        val v = o[i] + c + 65535
        c = v shr 16
        o[i] = v - (c shl 16)
    }
    o[0] += c - 1 + 37 * (c - 1)
}

internal fun gfAdd(o: Gf, a: Gf, b: Gf) {
    for (i in 0 until 16) o.n[i] = a.n[i] + b.n[i]
}

internal fun gfSub(o: Gf, a: Gf, b: Gf) {
    for (i in 0 until 16) o.n[i] = a.n[i] - b.n[i]
}

internal fun gfMul(o: Gf, a: Gf, b: Gf) {
    val t = LongArray(31)
    for (i in 0 until 16) {
        for (j in 0 until 16) t[i + j] += a.n[i] * b.n[j]
    }
    for (i in 0 until 15) t[i] += 38 * t[i + 16]
    for (i in 0 until 16) o.n[i] = t[i]
    gfCar(o.n)
    gfCar(o.n)
}

internal fun gfSqr(o: Gf, a: Gf) = gfMul(o, a, a)

internal fun gfInv(o: Gf, i: Gf) {
    val c = i.copy()
    for (a in 253 downTo 0) {
        gfSqr(c, c)
        if (a != 2 && a != 4) gfMul(c, c, i)
    }
    for (a in 0 until 16) o.n[a] = c.n[a]
}

internal fun unpack25519(o: Gf, n: ByteArray) {
    for (i in 0 until 16) o.n[i] = n.u8(2 * i).toLong() + (n.u8(2 * i + 1).toLong() shl 8)
    o.n[15] = o.n[15] and 0x7fff
}

internal fun pack25519(o: ByteArray, n: Gf) {
    val m = Gf()
    val t = n.copy()
    gfCar(t.n); gfCar(t.n); gfCar(t.n)
    for (j in 0 until 2) {
        m.n[0] = t.n[0] - 0xffed
        for (i in 1 until 15) {
            m.n[i] = t.n[i] - 0xffff - ((m.n[i - 1] shr 16) and 1)
            m.n[i - 1] = m.n[i - 1] and 0xffff
        }
        m.n[15] = t.n[15] - 0x7fff - ((m.n[14] shr 16) and 1)
        val b = (m.n[15] shr 16) and 1
        m.n[14] = m.n[14] and 0xffff
        sel25519(t, m, 1 - b.toInt())
    }
    for (i in 0 until 16) {
        o[2 * i] = t.n[i].toByte()
        o[2 * i + 1] = (t.n[i] shr 8).toByte()
    }
}

internal fun sel25519(p: Gf, q: Gf, b: Int) {
    val c = -b.toLong()
    for (i in 0 until 16) {
        val t = c and (p.n[i] xor q.n[i])
        p.n[i] = p.n[i] xor t
        q.n[i] = q.n[i] xor t
    }
}

private val GF_121665 = Gf(LongArray(16).also { it[0] = 121665 })

internal object X25519 {
    fun scalarMult(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == 32 && u.size == 32)
        val z = scalar.copyOf()
        z[31] = ((z[31].toInt() and 127) or 64).toByte()
        z[0] = (z[0].toInt() and 248).toByte()
        val a = Gf(); val b = Gf(); val c = Gf(); val d = Gf()
        val e = Gf(); val f = Gf(); val x = Gf()
        unpack25519(x, u)
        for (i in 0 until 16) {
            b.n[i] = x.n[i]
            d.n[i] = 0
            a.n[i] = 0
            c.n[i] = 0
        }
        a.n[0] = 1
        d.n[0] = 1
        for (i in 254 downTo 0) {
            val r = (z[i shr 3].toInt() ushr (i and 7)) and 1
            sel25519(a, b, r)
            sel25519(c, d, r)
            gfAdd(e, a, c)
            gfSub(a, a, c)
            gfAdd(c, b, d)
            gfSub(b, b, d)
            gfSqr(d, e)
            gfSqr(f, a)
            gfMul(a, c, a)
            gfMul(c, b, e)
            gfAdd(e, a, c)
            gfSub(a, a, c)
            gfSqr(b, a)
            gfSub(c, d, f)
            gfMul(a, c, GF_121665)
            gfAdd(a, a, d)
            gfMul(c, c, a)
            gfMul(a, d, f)
            gfMul(d, b, x)
            gfSqr(b, e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }
        gfInv(c, c)
        gfMul(a, a, c)
        val out = ByteArray(32)
        pack25519(out, a)
        return out
    }

    fun publicFromPrivate(secret: ByteArray): ByteArray {
        val nine = ByteArray(32)
        nine[0] = 9
        return scalarMult(secret, nine)
    }

    fun randomKeyPair(): Pair<ByteArray, ByteArray> {
        val secret = secureRandom(32)
        return secret to publicFromPrivate(secret)
    }
}
