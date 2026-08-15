package org.hazae41.echalote

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CryptoInitTest {
    @Test
    fun initBundledCryptoIsIdempotent() {
        initBundledCrypto()
        initBundledCrypto()
    }

    @Test
    fun sha1HashesKnownVector() {
        initBundledCrypto()
        val out = Sha1.hash(byteArrayOf(1, 2, 3))
        assertEquals(20, out.size)
        assertEquals("7037807198c22a7d2b0807371d763779a84fdfcf", bytesToHex(out))
    }

    @Test
    fun x25519ImportsNtorStylePublicKey() {
        initBundledCrypto()
        val pub = ByteArray(32)
        pub[0] = 0x89.toByte()
        pub[1] = 0x7b
        pub[31] = 0x01
        val secret = ByteArray(32) { 42 }
        val shared = X25519.scalarMult(secret, pub)
        assertEquals(32, shared.size)
    }

    @Test
    fun x25519Rfc7748Alice() {
        val secret = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val pub = X25519.publicFromPrivate(secret)
        assertEquals(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            bytesToHex(pub),
        )
    }

    @Test
    fun sha384AndSha512KnownVectors() {
        assertEquals(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            bytesToHex(Sha384.hash(utf8Bytes("abc"))),
        )
        assertEquals(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            bytesToHex(Sha512.hash(utf8Bytes("abc"))),
        )
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            bytesToHex(Sha256.hash(utf8Bytes("abc"))),
        )
    }

    @Test
    fun ed25519Rfc8032EmptyMessage() {
        val pk = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val sig = hexToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        assertTrue(Ed25519.verify(pk, ByteArray(0), sig))
        assertTrue(!Ed25519.verify(pk, byteArrayOf(1), sig))
    }

    @Test
    fun aesGcmNistSp80038d() {
        val key = hexToBytes("feffe9928665731c6d6a8d0340314de6988172eb668b13286cd15797890eaf44")
        val iv = hexToBytes("cafebabefacedbaddecaf888")
        val aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        val pt = hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        val (ct, tag) = AesGcm.encrypt(key, iv, aad, pt)
        val joined = bytesToHex(ct) + bytesToHex(tag)
        assertEquals(
            "baddcb51da4086d3636e3987396c3557381fb0d468e055957e8d8188dcab2ab87722ebd1d8674cdd40cd25c2d32fb16f21ffece9d756ad3daf896b95902ac1cec42e37482c2983140791dc66",
            joined,
        )
        assertTrue(AesGcm.decrypt(key, iv, aad, ct, tag).contentEquals(pt))
    }

    @Test
    fun p256Rfc5903Ecdh() {
        val dA = hexToBytes("C477F9F65C22CCE206BF6736CFB5F889E5B9818C9260146C49F6B99747C9AD77")
        val dB = hexToBytes("FE30F3577E7DBA5D9B3FCACEF592D06C6810EA26998F8FBABFAA7949544C6A8D")
        val (ax, ay) = P256.scalarMult(dA, P256.Gx, P256.Gy)
        val (bx, by) = P256.scalarMult(dB, P256.Gx, P256.Gy)
        assertEquals("3bfc8f0b293a7d04d5defa4e46d9416682a36bc7d73dc95822a5f400b4150cc0", bytesToHex(ax.toFixedBytes(32)))
        assertEquals("531877d79547e4e3e2068d56d02cb6f56ceb7960d2ff40cdab5e7f005a7c0a35", bytesToHex(ay.toFixedBytes(32)))
        val z = P256.ecdh(dA, P256.encodeUncompressed(bx, by))
        assertEquals("cd4556e232045594145e8785ec8bffda84eba04bda7aae8a17a7912f82db7ad4", bytesToHex(z))
    }
}
