package io.bluewallet.echalote

import io.bluewallet.echalote.vectors.RSA_PKCS1_VECTORS_JSON
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class RsaVerifyTest {
    private val vectors = Json.parseToJsonElement(RSA_PKCS1_VECTORS_JSON).jsonObject

    @Test
    fun initBundledIsSafeToCall() {
        RsaWasm.initBundled()
    }

    @Test
    fun wasmVectorsAcceptAndReject() {
        RsaWasm.initBundled()
        for (c in vectors["cases"]!!.jsonArray) {
            val obj = c.jsonObject
            val bits = obj["bits"]!!.jsonPrimitive.content
            val pub = RsaPublicKey.fromPublicKeyDer(Memory(hexToBytes(obj["spki"]!!.jsonPrimitive.content)))
            val hash = hexToBytes(obj["hash"]!!.jsonPrimitive.content)
            val sig = hexToBytes(obj["signature"]!!.jsonPrimitive.content)
            val wasm = obj["wasm"]!!.jsonObject
            assertEquals(wasm["good"]!!.jsonPrimitive.boolean, pub.verifyPkcs1v15Unprefixed(Memory(hash), Memory(sig)), "$bits-bit good")

            val bad = hash.copyOf()
            bad[0] = (bad[0].toInt() xor 1).toByte()
            assertEquals(wasm["badHash"]!!.jsonPrimitive.boolean, pub.verifyPkcs1v15Unprefixed(Memory(bad), Memory(sig)), "$bits-bit badHash")

            val short = sig.copyOfRange(0, sig.size - 1)
            assertEquals(wasm["shortSig"]!!.jsonPrimitive.boolean, pub.verifyPkcs1v15Unprefixed(Memory(hash), Memory(short)), "$bits-bit shortSig")

            val pkcs1 = RsaPublicKey.fromPkcs1Der(Memory(hexToBytes(obj["pkcs1"]!!.jsonPrimitive.content)))
            val pk = obj["pkcs1Case"]!!.jsonObject
            assertEquals(
                pk["wasmGood"]!!.jsonPrimitive.boolean,
                pkcs1.verifyPkcs1v15Unprefixed(
                    Memory(hexToBytes(pk["hash"]!!.jsonPrimitive.content)),
                    Memory(hexToBytes(pk["signature"]!!.jsonPrimitive.content)),
                ),
                "$bits-bit PKCS#1 DER",
            )
        }
    }

    /** Tor directory signatures: PKCS#1 v1.5 type-1 padding over the raw digest, no DigestInfo. */
    @Test
    fun rawDigestSignatureWithoutDigestInfoVerifies() {
        // openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pkcs1 over SHA-256("echalote raw digest vector")
        val key =
            RsaPublicKey.fromPkcs1Der(
                Memory(
                    Base64.decode(
                        "MIIBCgKCAQEAlbw28lyKzIbv/K4SsFx2fRbI4n0N+4WXoch/jOthjD594tCkIUtFIVyysTI5C6BzV/Cd" +
                            "0US34SIbdtDDTJmAlKMXz/j4WDFJ8NaDk9yWiJ3U0Uuonf8KeNalVKgRZiamwB3NxTQiLi5efZ1C9/1z" +
                            "LvqnEgCSlfdPbb3EKqtp3ZpHW2METlVTvs69Q4+oFiJt23kKjPH4sHdqHY6CN/y2t7AJX6XYg7HLlSTZ" +
                            "jUQpJqeUgbizz6LiTC2mUWnZGfZAv9DKz7ZZMnUWva+1n/DBjq2sqS/DiTCu3+n2IqzOylHAJmBc/Don" +
                            "nXitKd9yJiiv+pj5XJ/4JJxw0Ex3BuynrwIDAQAB",
                    ),
                ),
            )
        val digest = hexToBytes("8d9d9e3310869421975b54fc787443743bf087bd08550691130c52900918f3dc")
        val sig =
            hexToBytes(
                "21c65b4dec6691b26b8a0638e73a3be231148ada7bc5a2642535f8bac760c853d4d06a24c5da57ad" +
                    "80faf8ac05720ed604a99937a0ede4211fa46806323b6451d0771aaef4096fbd63454e44a1b70e56" +
                    "947e411787977d3d13f751f0788d2e374a284567ff781e7dee729fd986612d77d39f42269ba77339" +
                    "cb04be4e2879e025bc2d1adc159b2e661c36da5f52490e3a0749a943087136e5fa8e326b4f5177d7" +
                    "c0d11051244498ce8ff5eec0a91baad76ad8b3640f147f05cd57dbc461385cfbaf6db563582c8fee" +
                    "516b8995519c284ecf7f1a75e31722128f40f6634e2cbaf34e86a6aef8b240903fb3b5f7966620c7" +
                    "fd060919d1876b41f885b07724633ace",
            )
        assertEquals(true, key.verifyPkcs1v15Unprefixed(Memory(digest), Memory(sig)))
        assertEquals(false, key.verifyPkcs1v15Digest(RsaPublicKey.SHA256_DIGESTINFO, digest, sig))
        val bad = digest.copyOf().also { it[31] = (it[31].toInt() xor 1).toByte() }
        assertEquals(false, key.verifyPkcs1v15Unprefixed(Memory(bad), Memory(sig)))
    }
}
