package org.hazae41.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class MeekTest {
    @Test
    fun returnsStreamWithUrlAndSessionHeader() {
        val url = "https://example.test/meek/"
        val stream = createMeekStream(url)
        assertEquals(url, stream.url)
        assertTrue(stream.sessionId.isNotEmpty())
        stream.error(Exception("test teardown"))
    }

    @Test
    fun eachCallGetsDistinctSessionId() {
        val a = createMeekStream("https://example.test/a/")
        val b = createMeekStream("https://example.test/b/")
        assertTrue(a.sessionId.isNotEmpty())
        assertTrue(b.sessionId.isNotEmpty())
        assertNotEquals(a.sessionId, b.sessionId)
        a.error(Exception("test teardown"))
        b.error(Exception("test teardown"))
    }

    @Test
    fun defaultMeekUrlPointsAtCdn77() {
        assertEquals("https://1603026938.rsc.cdn77.org/", DEFAULT_MEEK_URL)
        assertFalse(DEFAULT_MEEK_URL.contains("azureedge.net"))
        assertFalse(DEFAULT_MEEK_URL.contains("meek.azureedge.net"))
    }

    @Test
    fun createMeekStreamWithNoUrlUsesDefault() {
        val stream = createMeekStream()
        assertEquals(DEFAULT_MEEK_URL, stream.url)
        stream.error(Exception("test teardown"))
    }

    @Test
    fun doesNotPostUntilFirstOutboundBytes() = runBlocking {
        var posts = 0
        val first = CompletableDeferred<Int>()
        val engine = HttpEngine { _, _, _, body, _, _ ->
            posts += 1
            if (!first.isCompleted) first.complete(body.size)
            HttpResponse(200, ByteArray(0))
        }
        val stream = createMeekStream("http://example.test/meek/", engine)
        stream.start()
        delay(40)
        assertEquals(0, posts)
        stream.duplex.write(byteArrayOf(1, 2, 3))
        val n = withTimeout(2_000) { first.await() }
        assertEquals(3, n)
        stream.error(Exception("test teardown"))
    }
}

