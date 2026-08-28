package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ChannelDuplexOrderTest {
    @Test
    fun sequential_enqueues_keep_relay_cell_order() = runBlocking {
        val duplex = ChannelDuplex()
        val chunks = (0 until 12).map { i ->
            ByteArray(498) { pos -> if (pos == 0) i.toByte() else 1 }
        }
        for (chunk in chunks) duplex.enqueue(chunk)
        duplex.close()
        val got = ArrayList<Byte>()
        while (true) {
            val piece = duplex.read(498)
            if (piece.isEmpty()) break
            got += piece.toList()
        }
        val expect = chunks.flatMap { it.toList() }
        assertEquals(expect.size, got.size)
        assertTrue(got == expect)
    }
}
