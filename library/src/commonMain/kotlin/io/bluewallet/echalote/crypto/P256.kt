package io.bluewallet.echalote

/**
 * NIST P-256 (secp256r1) ECDH in Jacobian coordinates.
 */
internal object P256 {
    val P = BigNat.fromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
    val N = BigNat.fromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    val B = BigNat.fromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
    val Gx = BigNat.fromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
    val Gy = BigNat.fromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    private val TWO = BigNat.fromBytes(byteArrayOf(2))
    private val THREE = BigNat.fromBytes(byteArrayOf(3))
    private val EIGHT = BigNat.fromBytes(byteArrayOf(8))
    private val P_MINUS_2 = P.subtract(TWO)

    class Point(val x: BigNat, val y: BigNat, val z: BigNat, val inf: Boolean = false) {
        companion object {
            val INF = Point(BigNat.ZERO, BigNat.ONE, BigNat.ZERO, inf = true)
        }
    }

    fun feAdd(a: BigNat, b: BigNat): BigNat = a.add(b).mod(P)
    fun feSub(a: BigNat, b: BigNat): BigNat {
        val aa = a.mod(P)
        val bb = b.mod(P)
        return if (aa.compare(bb) >= 0) aa.subtract(bb) else aa.add(P).subtract(bb)
    }
    fun feMul(a: BigNat, b: BigNat): BigNat = a.mul(b).mod(P)
    fun feSqr(a: BigNat): BigNat = feMul(a, a)
    fun feInv(a: BigNat): BigNat = a.modPow(P_MINUS_2, P)

    fun toAffine(p: Point): Pair<BigNat, BigNat> {
        require(!p.inf) { "infinity" }
        val zinv = feInv(p.z)
        val z2 = feSqr(zinv)
        val z3 = feMul(z2, zinv)
        return feMul(p.x, z2) to feMul(p.y, z3)
    }

    fun double(p: Point): Point {
        if (p.inf) return p
        val xx = feSqr(p.x)
        val yy = feSqr(p.y)
        val yyyy = feSqr(yy)
        val zz = feSqr(p.z)
        val s = feMul(TWO, feSub(feSub(feSqr(feAdd(p.x, yy)), xx), yyyy))
        val m = feMul(THREE, feSub(xx, feSqr(zz)))
        val t = feSub(feSqr(m), feMul(TWO, s))
        val x3 = t
        val y3 = feSub(feMul(m, feSub(s, t)), feMul(EIGHT, yyyy))
        val z3 = feSub(feSub(feSqr(feAdd(p.y, p.z)), yy), zz)
        if (z3.compare(BigNat.ZERO) == 0) return Point.INF
        return Point(x3, y3, z3)
    }

    fun add(p: Point, q: Point): Point {
        if (p.inf) return q
        if (q.inf) return p
        val z1z1 = feSqr(p.z)
        val z2z2 = feSqr(q.z)
        val u1 = feMul(p.x, z2z2)
        val u2 = feMul(q.x, z1z1)
        val s1 = feMul(p.y, feMul(q.z, z2z2))
        val s2 = feMul(q.y, feMul(p.z, z1z1))
        val h = feSub(u2, u1)
        val r = feSub(s2, s1)
        if (h.compare(BigNat.ZERO) == 0) {
            return if (r.compare(BigNat.ZERO) == 0) double(p) else Point.INF
        }
        val hh = feSqr(h)
        val hhh = feMul(h, hh)
        val v = feMul(u1, hh)
        val x3 = feSub(feSub(feSqr(r), hhh), feMul(TWO, v))
        val y3 = feSub(feMul(r, feSub(v, x3)), feMul(s1, hhh))
        val z3 = feMul(feMul(p.z, q.z), h)
        return Point(x3, y3, z3)
    }

    fun scalarMult(k: ByteArray, px: BigNat, py: BigNat): Pair<BigNat, BigNat> {
        var r = Point.INF
        val base = Point(px, py, BigNat.ONE)
        for (byte in k) {
            val b = byte.toInt() and 0xff
            for (bit in 7 downTo 0) {
                r = double(r)
                if ((b ushr bit) and 1 == 1) r = add(r, base)
            }
        }
        require(!r.inf) { "P-256 product is infinity" }
        return toAffine(r)
    }

    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        while (true) {
            val d = secureRandom(32)
            val dn = BigNat.fromBytes(d)
            if (dn.compare(BigNat.ZERO) == 0 || dn.compare(N) >= 0) continue
            val (x, y) = scalarMult(d, Gx, Gy)
            return d to encodeUncompressed(x, y)
        }
    }

    fun ecdh(secret: ByteArray, peerUncompressed: ByteArray): ByteArray {
        val (x, y) = decodeUncompressed(peerUncompressed)
        val (sx, _) = scalarMult(secret, x, y)
        return sx.toFixedBytes(32)
    }

    fun encodeUncompressed(x: BigNat, y: BigNat): ByteArray =
        concatBytes(byteArrayOf(0x04), x.toFixedBytes(32), y.toFixedBytes(32))

    fun decodeUncompressed(p: ByteArray): Pair<BigNat, BigNat> {
        require(p.size == 65 && p[0].toInt() == 0x04) { "P-256 point must be uncompressed" }
        val x = BigNat.fromBytes(p.copyOfRange(1, 33))
        val y = BigNat.fromBytes(p.copyOfRange(33, 65))
        val yy = feSqr(y)
        val rhs = feAdd(feSub(feMul(feSqr(x), x), feMul(THREE, x)), B)
        require(yy.compare(rhs) == 0) { "P-256 point not on curve" }
        return x to y
    }
}
