package io.bluewallet.echalote

import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

internal actual fun platformRsaPublicOp(
    signature: ByteArray,
    exponent: ByteArray,
    modulus: ByteArray,
    outLen: Int,
): ByteArray? {
    val m = BigInteger(1, signature).modPow(BigInteger(1, exponent), BigInteger(1, modulus))
    return unsignedFixed(m.toByteArray(), outLen)
}

internal actual fun platformP256Ecdh(peerUncompressed: ByteArray): Pair<ByteArray, ByteArray>? =
    try {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val ours = kpg.generateKeyPair()
        val pub = ours.public as ECPublicKey
        val peerPoint =
            ECPoint(
                BigInteger(1, peerUncompressed.copyOfRange(1, 33)),
                BigInteger(1, peerUncompressed.copyOfRange(33, 65)),
            )
        val peer = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(peerPoint, pub.params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(ours.private)
        ka.doPhase(peer, true)
        val shared = unsignedFixed(ka.generateSecret(), 32)
        val encoded =
            concatBytes(
                byteArrayOf(0x04),
                unsignedFixed(pub.w.affineX.toByteArray(), 32),
                unsignedFixed(pub.w.affineY.toByteArray(), 32),
            )
        encoded to shared
    } catch (_: GeneralSecurityException) {
        null
    }
