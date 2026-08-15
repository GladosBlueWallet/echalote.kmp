package org.hazae41.echalote

/** Pure Kotlin zlib/deflate inflater (RFC 1950/1951) for native targets. */
internal object InflateKt {
    fun inflateZlibOrNull(input: ByteArray): ByteArray? {
        if (input.size < 2 || (input[0].toInt() and 0xff) != 0x78) return null
        return try {
            inflateDeflate(input, 2)
        } catch (_: Exception) {
            null
        }
    }

    private class BitReader(val src: ByteArray, var i: Int) {
        var bitBuf = 0
        var bitCnt = 0
        fun bits(n: Int): Int {
            while (bitCnt < n) {
                if (i >= src.size) throw IllegalArgumentException("truncated deflate")
                bitBuf = bitBuf or (src.u8(i++) shl bitCnt)
                bitCnt += 8
            }
            val v = bitBuf and ((1 shl n) - 1)
            bitBuf = bitBuf ushr n
            bitCnt -= n
            return v
        }
        fun byteAlign() {
            bitBuf = 0
            bitCnt = 0
        }
    }

    private class Huffman(val counts: IntArray, val symbols: IntArray, val maxBits: Int)

    private fun buildHuffman(lengths: IntArray): Huffman {
        val maxBits = lengths.maxOrNull() ?: 0
        val counts = IntArray(maxBits + 1)
        for (l in lengths) if (l > 0) counts[l]++
        val offsets = IntArray(maxBits + 1)
        offsets[1] = 0
        for (i in 1 until maxBits) offsets[i + 1] = offsets[i] + counts[i]
        val symbols = IntArray(lengths.size)
        val next = offsets.copyOf()
        for (sym in lengths.indices) {
            val l = lengths[sym]
            if (l != 0) {
                symbols[next[l]] = sym
                next[l]++
            }
        }
        return Huffman(counts, symbols, maxBits)
    }

    private fun decodeSymbol(r: BitReader, h: Huffman): Int {
        var code = 0
        var first = 0
        var index = 0
        for (len in 1..h.maxBits) {
            code = code or r.bits(1)
            val count = if (len < h.counts.size) h.counts[len] else 0
            if (code - count < first) {
                return h.symbols[index + (code - first)]
            }
            index += count
            first += count
            first = first shl 1
            code = code shl 1
        }
        throw IllegalArgumentException("bad huffman symbol")
    }

    private val LEN_BASE = intArrayOf(
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
    )
    private val LEN_EXTRA = intArrayOf(
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    )
    private val DIST_BASE = intArrayOf(
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    )
    private val DIST_EXTRA = intArrayOf(
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    )
    private val CL_ORDER = intArrayOf(16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15)

    private fun inflateDeflate(src: ByteArray, start: Int): ByteArray {
        val r = BitReader(src, start)
        val out = ArrayList<Byte>(src.size * 2)
        while (true) {
            val last = r.bits(1)
            when (r.bits(2)) {
                0 -> inflateStored(r, out)
                1 -> inflateHuffman(r, out, fixedLit(), fixedDist())
                2 -> {
                    val (lit, dist) = readDynamic(r)
                    inflateHuffman(r, out, lit, dist)
                }
                else -> throw IllegalArgumentException("invalid block type")
            }
            if (last == 1) break
        }
        return ByteArray(out.size) { out[it] }
    }

    private fun inflateStored(r: BitReader, out: ArrayList<Byte>) {
        r.byteAlign()
        if (r.i + 4 > r.src.size) throw IllegalArgumentException("truncated stored")
        val len = r.src.u8(r.i) or (r.src.u8(r.i + 1) shl 8)
        val nlen = r.src.u8(r.i + 2) or (r.src.u8(r.i + 3) shl 8)
        r.i += 4
        if (len xor 0xffff != nlen) throw IllegalArgumentException("stored nlen mismatch")
        for (i in 0 until len) {
            out += r.src[r.i++].toByte()
        }
    }

    private fun inflateHuffman(r: BitReader, out: ArrayList<Byte>, lit: Huffman, dist: Huffman) {
        while (true) {
            val sym = decodeSymbol(r, lit)
            when {
                sym < 256 -> out += sym.toByte()
                sym == 256 -> return
                else -> {
                    val idx = sym - 257
                    val length = LEN_BASE[idx] + r.bits(LEN_EXTRA[idx])
                    val ds = decodeSymbol(r, dist)
                    val distance = DIST_BASE[ds] + r.bits(DIST_EXTRA[ds])
                    val start = out.size - distance
                    require(start >= 0) { "invalid distance" }
                    repeat(length) { out += out[out.size - distance] }
                }
            }
        }
    }

    private fun readDynamic(r: BitReader): Pair<Huffman, Huffman> {
        val hlit = r.bits(5) + 257
        val hdist = r.bits(5) + 1
        val hclen = r.bits(4) + 4
        val clen = IntArray(19)
        for (i in 0 until hclen) clen[CL_ORDER[i]] = r.bits(3)
        val cl = buildHuffman(clen)
        val lengths = IntArray(hlit + hdist)
        var n = 0
        while (n < lengths.size) {
            val s = decodeSymbol(r, cl)
            when (s) {
                in 0..15 -> lengths[n++] = s
                16 -> {
                    val prev = if (n == 0) 0 else lengths[n - 1]
                    val rep = 3 + r.bits(2)
                    repeat(rep) { lengths[n++] = prev }
                }
                17 -> {
                    val rep = 3 + r.bits(3)
                    n += rep
                }
                18 -> {
                    val rep = 11 + r.bits(7)
                    n += rep
                }
                else -> throw IllegalArgumentException("bad clen")
            }
        }
        val lit = buildHuffman(lengths.copyOf(hlit))
        val dist = buildHuffman(lengths.copyOfRange(hlit, lengths.size))
        return lit to dist
    }

    private fun fixedLit(): Huffman {
        val l = IntArray(288)
        for (i in 0..143) l[i] = 8
        for (i in 144..255) l[i] = 9
        for (i in 256..279) l[i] = 7
        for (i in 280..287) l[i] = 8
        return buildHuffman(l)
    }

    private fun fixedDist(): Huffman {
        val l = IntArray(32) { 5 }
        return buildHuffman(l)
    }
}
