package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

/** The JVM/Android platform crypto must agree with the pure-Kotlin fallback used on iOS/Linux. */
class PlatformCryptoJvmTest {
    @Test
    fun platformP256EcdhAgreesWithPureKotlin() {
        repeat(3) {
            val (secret, kotlinPublic) = P256.generateKeyPair()
            val (platformPublic, shared) = platformP256Ecdh(kotlinPublic)!!
            assertEquals(65, platformPublic.size)
            P256.decodeUncompressed(platformPublic) // on the curve
            assertContentEquals(P256.ecdh(secret, platformPublic), shared)
        }
    }

    @Test
    fun offCurvePeerPointIsRejectedBeforeThePlatform() {
        val (_, pub) = P256.generateKeyPair()
        pub[64] = (pub[64].toInt() xor 1).toByte()
        assertFails { P256.decodeUncompressed(pub) }
    }

    @Test
    fun platformRsaPublicOpAgreesWithBigNat() {
        val modulus =
            secureRandom(256).also {
                it[0] = (it[0].toInt() or 0x80).toByte()
                it[255] = (it[255].toInt() or 1).toByte()
            }
        val exponent = byteArrayOf(1, 0, 1)
        repeat(5) {
            val base = secureRandom(256).also { it[0] = (it[0].toInt() and 0x3f).toByte() }
            val want = BigNat.fromBytes(base).modPow(BigNat.fromBytes(exponent), BigNat.fromBytes(modulus)).toFixedBytes(256)
            assertContentEquals(want, platformRsaPublicOp(base, exponent, modulus, 256))
        }
    }

    @Test
    fun unsignedFixedPadsAndStripsSignByte() {
        assertContentEquals(byteArrayOf(0, 0, 0x7f), unsignedFixed(byteArrayOf(0x7f), 3))
        assertContentEquals(byteArrayOf(0x80.toByte(), 1), unsignedFixed(byteArrayOf(0, 0x80.toByte(), 1), 2))
        assertFails { unsignedFixed(byteArrayOf(1, 2, 3), 2) }
    }
}
