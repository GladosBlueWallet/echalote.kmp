package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.TimeSource

/** Each platform's inflater (libz / java.util.zip) must agree with the pure-Kotlin InflateKt. */
class InflateParityTest {
    private val zlib by lazy { readTestFixture("consensus/consensus-microdesc-2026-10-22-0200.z") }

    @Test
    fun platformZlibMatchesPureKotlinOnRealConsensus() {
        val t0 = TimeSource.Monotonic.markNow()
        val want = assertNotNull(InflateKt.inflateZlibOrNull(zlib))
        val pureMs = t0.elapsedNow().inWholeMilliseconds
        val t1 = TimeSource.Monotonic.markNow()
        val got = assertNotNull(inflateZlibOrNull(zlib))
        val platformMs = t1.elapsedNow().inWholeMilliseconds
        println("inflate consensus ${zlib.size}->${want.size} bytes: pure-Kotlin ${pureMs}ms, platform ${platformMs}ms")
        assertContentEquals(want, got)
    }

    @Test
    fun platformZlibRejectsTruncatedAndCorrupt() {
        assertEquals(null, inflateZlibOrNull(zlib.copyOf(zlib.size / 2)))
        assertEquals(null, inflateZlibOrNull(zlib.copyOf(zlib.size - 2)))
        val badAdler = zlib.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(null, inflateZlibOrNull(badAdler))
        assertEquals(null, inflateZlibOrNull("not zlib at all, really".encodeToByteArray()))
    }

    @Test
    fun platformGzipMatchesPureKotlin() {
        val plain = assertNotNull(InflateKt.inflateZlibOrNull(zlib))
        // Re-wrap the same deflate data as a gzip member: header + deflate + CRC-32 + ISIZE.
        val deflate = zlib.copyOfRange(2, zlib.size - 4)
        val header = byteArrayOf(0x1f, 0x8b.toByte(), 8, 0, 0, 0, 0, 0, 0, 0xff.toByte())
        val gz = concatBytes(header, deflate, le32(crc32(plain)), le32(plain.size.toLong()))
        assertContentEquals(plain, assertNotNull(InflateKt.inflateGzipOrNull(gz)))
        assertContentEquals(plain, assertNotNull(inflateGzipOrNull(gz)))
        val badCrc = gz.copyOf().also { it[it.size - 6] = (it[it.size - 6].toInt() xor 1).toByte() }
        assertEquals(null, inflateGzipOrNull(badCrc))
        assertEquals(null, inflateGzipOrNull(gz.copyOf(gz.size - 3)))
    }

    private fun le32(v: Long): ByteArray = ByteArray(4) { i -> (v shr (8 * i)).toByte() }

    private fun crc32(data: ByteArray): Long {
        var c = 0xffffffffL
        for (b in data) {
            c = c xor (b.toLong() and 0xff)
            repeat(8) { c = if (c and 1L != 0L) (c ushr 1) xor 0xedb88320L else c ushr 1 }
        }
        return c xor 0xffffffffL
    }
}
