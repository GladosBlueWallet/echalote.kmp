package io.bluewallet.echalote

class Cursor(
    val bytes: ByteArray,
    var offset: Int = 0,
    val end: Int = bytes.size,
) {
    val remaining: Int get() = end - offset

    fun write(src: ByteArray, srcOff: Int = 0, len: Int = src.size - srcOff) {
        require(remaining >= len) { "cursor overflow writing $len" }
        src.copyInto(bytes, offset, srcOff, srcOff + len)
        offset += len
    }

    fun writeU8(v: Int) {
        require(remaining >= 1) { "cursor overflow writing u8" }
        bytes[offset] = v.toByte()
        offset += 1
    }

    fun writeU16(v: Int) {
        require(remaining >= 2) { "cursor overflow writing u16" }
        bytes.putU16be(offset, v)
        offset += 2
    }

    fun writeU32(v: Int) {
        require(remaining >= 4) { "cursor overflow writing u32" }
        bytes.putU32be(offset, v)
        offset += 4
    }

    fun writeNulled(src: ByteArray) {
        write(src)
        writeU8(0)
    }

    fun fill(value: Int, n: Int) {
        require(remaining >= n) { "cursor overflow filling $n" }
        val b = value.toByte()
        for (i in 0 until n) bytes[offset + i] = b
        offset += n
    }

    fun read(n: Int): ByteArray {
        require(remaining >= n) { "cursor underflow reading $n" }
        val out = bytes.copyOfRange(offset, offset + n)
        offset += n
        return out
    }

    /** Advance and return a cursor over the same backing array. */
    fun readView(n: Int): Cursor {
        require(remaining >= n) { "cursor underflow reading $n" }
        val view = Cursor(bytes, offset, offset + n)
        offset += n
        return view
    }

    fun peek(n: Int): ByteArray {
        require(remaining >= n) { "cursor underflow peeking $n" }
        return bytes.copyOfRange(offset, offset + n)
    }

    fun readU8(): Int {
        require(remaining >= 1) { "cursor underflow reading u8" }
        val v = bytes.u8(offset)
        offset += 1
        return v
    }

    fun readU16(): Int {
        require(remaining >= 2) { "cursor underflow reading u16" }
        val v = bytes.u16be(offset)
        offset += 2
        return v
    }

    fun readU32(): Int {
        require(remaining >= 4) { "cursor underflow reading u32" }
        val v = bytes.u32be(offset)
        offset += 4
        return v
    }

    fun readNulled(): ByteArray {
        var i = offset
        while (i < end && bytes[i].toInt() != 0) i++
        if (i >= end) throw IllegalArgumentException("missing NUL")
        val out = bytes.copyOfRange(offset, i)
        offset = i + 1
        return out
    }

    fun skipRemaining() {
        offset = end
    }

    fun split(n: Int): List<ByteArray> {
        val chunks = ArrayList<ByteArray>()
        while (remaining > 0) {
            val take = minOf(n, remaining)
            chunks += read(take)
        }
        return chunks
    }

    companion object {
        fun allocate(n: Int): Cursor = Cursor(ByteArray(n))
    }
}

class Opaque(val bytes: ByteArray) {
    fun size(): Int = bytes.size
    fun write(cursor: Cursor) {
        cursor.write(bytes)
    }
}
