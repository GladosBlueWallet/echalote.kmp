package org.hazae41.echalote

/**
 * Ed25519 verify, ported from public-domain TweetNaCl.
 */
internal object Ed25519 {
    private val gf0 = Gf()
    private val gf1 = Gf(LongArray(16).also { it[0] = 1 })
    private val D = gfOf(
        0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
    )
    private val D2 = gfOf(
        0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
    )
    private val X = gfOf(
        0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169,
    )
    private val Y = gfOf(
        0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
    )
    private val I = gfOf(
        0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
    )
    private val L = longArrayOf(
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    )

    private class Pt(val x: Gf = Gf(), val y: Gf = Gf(), val z: Gf = Gf(), val t: Gf = Gf()) {
        fun arr() = arrayOf(x, y, z, t)
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val sm = concatBytes(signature, message)
        val m = sm.copyOf()
        return cryptoSignOpen(m, sm, sm.size, publicKey)
    }

    private fun gfOf(vararg limbs: Long) = Gf(LongArray(16) { limbs[it] })

    private fun set25519(r: Gf, a: Gf) {
        a.n.copyInto(r.n)
    }

    private fun pow2523(o: Gf, i: Gf) {
        val c = i.copy()
        for (a in 250 downTo 0) {
            gfSqr(c, c)
            if (a != 1) gfMul(c, c, i)
        }
        c.n.copyInto(o.n)
    }

    private fun neq25519(a: Gf, b: Gf): Boolean {
        val c = ByteArray(32)
        val d = ByteArray(32)
        pack25519(c, a)
        pack25519(d, b)
        return !equalBytes(c, d)
    }

    private fun par25519(a: Gf): Int {
        val d = ByteArray(32)
        pack25519(d, a)
        return d[0].toInt() and 1
    }

    private fun add(p: Pt, q: Pt) {
        val a = Gf(); val b = Gf(); val c = Gf(); val d = Gf()
        val e = Gf(); val f = Gf(); val g = Gf(); val h = Gf(); val t = Gf()
        gfSub(a, p.y, p.x)
        gfSub(t, q.y, q.x)
        gfMul(a, a, t)
        gfAdd(b, p.x, p.y)
        gfAdd(t, q.x, q.y)
        gfMul(b, b, t)
        gfMul(c, p.t, q.t)
        gfMul(c, c, D2)
        gfMul(d, p.z, q.z)
        gfAdd(d, d, d)
        gfSub(e, b, a)
        gfSub(f, d, c)
        gfAdd(g, d, c)
        gfAdd(h, b, a)
        gfMul(p.x, e, f)
        gfMul(p.y, h, g)
        gfMul(p.z, g, f)
        gfMul(p.t, e, h)
    }

    private fun cswap(p: Pt, q: Pt, b: Int) {
        sel25519(p.x, q.x, b)
        sel25519(p.y, q.y, b)
        sel25519(p.z, q.z, b)
        sel25519(p.t, q.t, b)
    }

    private fun pack(r: ByteArray, p: Pt) {
        val tx = Gf(); val ty = Gf(); val zi = Gf()
        gfInv(zi, p.z)
        gfMul(tx, p.x, zi)
        gfMul(ty, p.y, zi)
        pack25519(r, ty)
        r[31] = (r[31].toInt() xor (par25519(tx) shl 7)).toByte()
    }

    private fun scalarmult(p: Pt, q: Pt, s: ByteArray) {
        set25519(p.x, gf0)
        set25519(p.y, gf1)
        set25519(p.z, gf1)
        set25519(p.t, gf0)
        for (i in 255 downTo 0) {
            val b = (s[i / 8].toInt() ushr (i and 7)) and 1
            cswap(p, q, b)
            add(q, p)
            add(p, p)
            cswap(p, q, b)
        }
    }

    private fun scalarbase(p: Pt, s: ByteArray) {
        val q = Pt()
        set25519(q.x, X)
        set25519(q.y, Y)
        set25519(q.z, gf1)
        gfMul(q.t, X, Y)
        scalarmult(p, q, s)
    }

    private fun modL(r: ByteArray, x: LongArray) {
        var carry: Long
        for (i in 63 downTo 32) {
            carry = 0
            var j = i - 32
            val k = i - 12
            while (j < k) {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128).floorDiv(256)
                x[j] -= carry * 256
                j++
            }
            x[j] += carry
            x[i] = 0
        }
        carry = 0
        for (j in 0 until 32) {
            x[j] += carry - (x[31] shr 4) * L[j]
            carry = x[j] shr 8
            x[j] = x[j] and 255
        }
        for (j in 0 until 32) x[j] -= carry * L[j]
        for (i in 0 until 32) {
            x[i + 1] += x[i] shr 8
            r[i] = (x[i] and 255).toByte()
        }
    }

    private fun reduce(r: ByteArray) {
        val x = LongArray(64) { r.u8(it).toLong() }
        for (i in r.indices) r[i] = 0
        modL(r, x)
    }

    private fun unpackneg(r: Pt, p: ByteArray): Boolean {
        val t = Gf(); val chk = Gf(); val num = Gf()
        val den = Gf(); val den2 = Gf(); val den4 = Gf(); val den6 = Gf()
        set25519(r.z, gf1)
        unpack25519(r.y, p)
        gfSqr(num, r.y)
        gfMul(den, num, D)
        gfSub(num, num, r.z)
        gfAdd(den, r.z, den)
        gfSqr(den2, den)
        gfSqr(den4, den2)
        gfMul(den6, den4, den2)
        gfMul(t, den6, num)
        gfMul(t, t, den)
        pow2523(t, t)
        gfMul(t, t, num)
        gfMul(t, t, den)
        gfMul(t, t, den)
        gfMul(r.x, t, den)
        gfSqr(chk, r.x)
        gfMul(chk, chk, den)
        if (neq25519(chk, num)) gfMul(r.x, r.x, I)
        gfSqr(chk, r.x)
        gfMul(chk, chk, den)
        if (neq25519(chk, num)) return false
        if (par25519(r.x) == ((p[31].toInt() and 0xff) ushr 7)) gfSub(r.x, gf0, r.x)
        gfMul(r.t, r.x, r.y)
        return true
    }

    private fun cryptoSignOpen(m: ByteArray, sm: ByteArray, n: Int, pk: ByteArray): Boolean {
        if (n < 64) return false
        val q = Pt()
        if (!unpackneg(q, pk)) return false
        sm.copyInto(m, 0, 0, n)
        pk.copyInto(m, 32)
        val h = Sha512.hash(m.copyOf(n))
        reduce(h)
        val p = Pt()
        scalarmult(p, q, h)
        scalarbase(q, sm.copyOfRange(32, 64))
        add(p, q)
        val t = ByteArray(32)
        pack(t, p)
        return equalBytes(sm.copyOfRange(0, 32), t)
    }
}
