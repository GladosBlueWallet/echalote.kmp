package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.TimeSource

/** Security.framework RSA / P-256 must be available on iOS and agree with the pure-Kotlin code. */
class PlatformCryptoIosTest {
    @Test
    fun platformP256EcdhAgreesWithPureKotlin() {
        repeat(3) {
            val (secret, kotlinPublic) = P256.generateKeyPair()
            val t = TimeSource.Monotonic.markNow()
            val (platformPublic, shared) = assertNotNull(platformP256Ecdh(kotlinPublic), "Security.framework ECDH unavailable")
            println("ios ecdh platform ${t.elapsedNow().inWholeMilliseconds}ms")
            assertEquals(65, platformPublic.size)
            P256.decodeUncompressed(platformPublic)
            assertContentEquals(P256.ecdh(secret, platformPublic), shared)
        }
    }

    @Test
    fun platformRsaPublicOpAgreesWithBigNat() {
        for (bits in listOf(1024, 2048, 3072)) {
            val k = bits / 8
            val modulus =
                secureRandom(k).also {
                    it[0] = (it[0].toInt() or 0x80).toByte()
                    it[k - 1] = (it[k - 1].toInt() or 1).toByte()
                }
            for (exponent in listOf(byteArrayOf(1, 0, 1), byteArrayOf(3))) {
                repeat(2) { round ->
                    val base = secureRandom(k).also { it[0] = (it[0].toInt() and 0x3f).toByte() }
                    // Also a base with leading zero bytes (shorter than the modulus as an integer).
                    if (round == 1) base.fill(0, 0, 5)
                    val t0 = TimeSource.Monotonic.markNow()
                    val want =
                        BigNat.fromBytes(base).modPow(BigNat.fromBytes(exponent), BigNat.fromBytes(modulus)).toFixedBytes(k)
                    val pureMs = t0.elapsedNow().inWholeMilliseconds
                    val t1 = TimeSource.Monotonic.markNow()
                    val got = assertNotNull(platformRsaPublicOp(base, exponent, modulus, k), "Security.framework RSA unavailable")
                    println("ios rsa-$bits e=${exponent.size}B pure ${pureMs}ms platform ${t1.elapsedNow().inWholeMilliseconds}ms")
                    assertContentEquals(want, got)
                }
            }
        }
    }

    @Test
    fun threadNamesAreDistinct() {
        val name = currentThreadName()
        println("ios test thread name: $name")
        kotlin.test.assertTrue(name == "main" || name.startsWith("t"))
    }
}
