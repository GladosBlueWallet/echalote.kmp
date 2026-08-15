package org.hazae41.echalote

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.hazae41.echalote.vectors.RSA_PKCS1_VECTORS_JSON
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
}
