package org.hazae41.echalote

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.hazae41.echalote.vectors.AES_CTR_VECTORS_JSON
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AesCtrTest {
    private val vectors = Json.parseToJsonElement(AES_CTR_VECTORS_JSON).jsonObject

    @Test
    fun initBundledIsSafeToCall() {
        AesWasm.initBundled()
    }

    @Test
    fun singleFullBlockAndCounterAdvance() {
        AesWasm.initBundled()
        val fb = vectors["fullBlock"]!!.jsonObject
        val k = Aes128Ctr128BEKey(Memory(hexToBytes(fb["key"]!!.jsonPrimitive.content)), Memory(hexToBytes(fb["iv"]!!.jsonPrimitive.content)))
        val m = Memory(hexToBytes(fb["plain"]!!.jsonPrimitive.content))
        k.applyKeystream(m)
        assertEquals(fb["after1"]!!.jsonPrimitive.content, bytesToHex(m.bytes))
        val m2 = Memory(ByteArray(16))
        k.applyKeystream(m2)
        assertEquals(fb["after2"]!!.jsonPrimitive.content, bytesToHex(m2.bytes))
    }

    @Test
    fun midBlockOffset1Plus15EqualsOne16ByteCall() {
        AesWasm.initBundled()
        val v = vectors["midBlock"]!!.jsonObject
        val split = Aes128Ctr128BEKey(Memory(hexToBytes(v["key"]!!.jsonPrimitive.content)), Memory(hexToBytes(v["iv"]!!.jsonPrimitive.content)))
        val a = Memory(hexToBytes(v["chunkAPlain"]!!.jsonPrimitive.content))
        val b = Memory(hexToBytes(v["chunkBPlain"]!!.jsonPrimitive.content))
        split.applyKeystream(a)
        split.applyKeystream(b)
        assertEquals(v["chunkAAfter"]!!.jsonPrimitive.content, bytesToHex(a.bytes))
        assertEquals(v["chunkBAfter"]!!.jsonPrimitive.content, bytesToHex(b.bytes))

        val once = Aes128Ctr128BEKey(Memory(hexToBytes(v["key"]!!.jsonPrimitive.content)), Memory(hexToBytes(v["iv"]!!.jsonPrimitive.content)))
        val c = Memory(hexToBytes(v["fullPlain"]!!.jsonPrimitive.content))
        once.applyKeystream(c)
        assertEquals(v["fullAfter"]!!.jsonPrimitive.content, bytesToHex(c.bytes))
        assertEquals(v["fullAfter"]!!.jsonPrimitive.content, bytesToHex(a.bytes) + bytesToHex(b.bytes))
    }

    @Test
    fun consecutive509ByteTorRelayPayloads() {
        AesWasm.initBundled()
        val relay = vectors["relay509"]!!.jsonObject
        val k = Aes128Ctr128BEKey(Memory(hexToBytes(relay["key"]!!.jsonPrimitive.content)), Memory(hexToBytes(relay["iv"]!!.jsonPrimitive.content)))
        for (round in relay["rounds"]!!.jsonArray) {
            val obj = round.jsonObject
            val plain = ByteArray(509) { obj["plainFill"]!!.jsonPrimitive.int.toByte() }
            val m = Memory(plain)
            k.applyKeystream(m)
            assertEquals(obj["after"]!!.jsonPrimitive.content, bytesToHex(m.bytes))
        }
    }

    @Test
    fun freshKeysOddLengths() {
        AesWasm.initBundled()
        for (item in vectors["oddLengths"]!!.jsonArray) {
            val obj = item.jsonObject
            val k = Aes128Ctr128BEKey(Memory(hexToBytes(obj["key"]!!.jsonPrimitive.content)), Memory(hexToBytes(obj["iv"]!!.jsonPrimitive.content)))
            val m = Memory(hexToBytes(obj["plain"]!!.jsonPrimitive.content))
            k.applyKeystream(m)
            assertEquals(obj["after"]!!.jsonPrimitive.content, bytesToHex(m.bytes), "len=${obj["len"]}")
        }
    }

    @Test
    fun memoryExposesMutableBytes() {
        val m = Memory(byteArrayOf(9, 8, 7))
        assertEquals(3, m.len())
        assertTrue(m.bytes.contentEquals(byteArrayOf(9, 8, 7)))
        m.bytes[0] = 1
        assertEquals(1, m.bytes[0].toInt())
    }
}
