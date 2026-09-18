package io.bluewallet.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StreamFetchTest {
    private fun utf8(s: String) = s.encodeToByteArray()

    private class MockDuplex(
        private val responseChunks: List<ByteArray>,
        private val keepOpen: Boolean = false,
        private val dropOnClose: Boolean = false,
    ) : ByteDuplex {
        private val req = ArrayList<ByteArray>()
        private val written = kotlinx.coroutines.CompletableDeferred<Unit>()
        private var idx = 0
        var closed = false
            private set

        override suspend fun read(n: Int): ByteArray {
            written.await()
            if (closed && dropOnClose) return ByteArray(0)
            if (idx >= responseChunks.size) {
                if (keepOpen) {
                    kotlinx.coroutines.CompletableDeferred<ByteArray>().await()
                }
                return ByteArray(0)
            }
            return responseChunks[idx++]
        }

        override suspend fun write(bytes: ByteArray) {
            req += bytes
            if (!written.isCompleted) written.complete(Unit)
        }

        override fun close() {
            closed = true
            if (!written.isCompleted) written.complete(Unit)
        }

        suspend fun requestText(): String {
            written.await()
            return req.fold(ByteArray(0)) { a, c -> concatBytes(a, c) }.decodeToString()
        }
    }

    @Test
    fun parsesContentLengthJsonAcrossFragmentedReads() =
        runTest {
            val body = """{"IsTor":true,"IP":"1.2.3.4"}"""
            val full = utf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")
            val mock =
                MockDuplex(
                    listOf(full.copyOfRange(0, 12), full.copyOfRange(12, 40), full.copyOfRange(40, full.size)),
                )
            val res = streamFetch("https://check.torproject.org/api/ip", StreamFetchInit(mock))
            assertEquals(200, res.status)
            val json = res.jsonObject()
            assertEquals("true", json["IsTor"])
            assertEquals("1.2.3.4", json["IP"])
            val req = mock.requestText().lowercase()
            assertTrue(req.startsWith("get /api/ip http/1.1\r\n"))
            assertTrue(req.contains("host: check.torproject.org\r\n"))
            assertTrue(req.contains("connection: keep-alive\r\n"))
            assertTrue(req.contains("user-agent: mozilla/5.0"))
            assertFalse(mock.closed)
        }

    @Test
    fun postsJsonBodyWithContentLength() =
        runTest {
            val reply = """{"ok":true}"""
            val mock =
                MockDuplex(
                    listOf(utf8("HTTP/1.1 200 OK\r\nContent-Length: ${reply.length}\r\n\r\n$reply")),
                )
            val payload = """{"a":1}""".encodeToByteArray()
            val res =
                streamFetch(
                    "https://api.rocketx.exchange/v1/quote",
                    StreamFetchInit(
                        mock,
                        method = "POST",
                        headers = mapOf("Content-Type" to "application/json"),
                        body = payload,
                    ),
                )
            assertEquals(200, res.status)
            assertEquals(reply, res.text())
            val req = mock.requestText()
            assertTrue(req.startsWith("POST /v1/quote HTTP/1.1\r\n"))
            assertTrue(req.contains("Content-Type: application/json"))
            assertTrue(req.contains("Content-Length: ${payload.size}"))
            assertTrue(req.contains("\r\n\r\n{\"a\":1}"))
            assertFalse(mock.closed)
        }

    @Test
    fun doesNotFullCloseWriteSideBeforeReadingResponse() =
        runTest {
            val body = """{"IsTor":true,"IP":"9.9.9.9"}"""
            val mock =
                MockDuplex(
                    listOf(utf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")),
                    dropOnClose = true,
                )
            val res = streamFetch("https://check.torproject.org/api/ip", StreamFetchInit(mock))
            assertEquals("true", res.jsonObject()["IsTor"])
            assertEquals("9.9.9.9", res.jsonObject()["IP"])
            assertFalse(mock.closed)
        }

    @Test
    fun finishesContentLengthWithoutWaitingForStreamClose() =
        runTest {
            val body = "ok"
            val mock =
                MockDuplex(
                    listOf(utf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")),
                    keepOpen = true,
                )
            val res = streamFetch("http://localhost/", StreamFetchInit(mock))
            assertEquals("ok", res.text())
        }

    @Test
    fun reassemblesChunkedBody() =
        runTest {
            val mock =
                MockDuplex(
                    listOf(
                        utf8("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"),
                        utf8("5\r\nhello\r\n"),
                        utf8("6\r\n world\r\n0\r\n\r\n"),
                    ),
                )
            val res = streamFetch("http://localhost/x", StreamFetchInit(mock))
            assertEquals("hello world", res.text())
        }

    @Test
    fun honorsContentLengthIgnoresBytesPastLength() =
        runTest {
            val mock = MockDuplex(listOf(utf8("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcdEXTRA")))
            val res = streamFetch("http://localhost/", StreamFetchInit(mock))
            assertEquals("abcd", res.text())
        }

    @Test
    fun rejectsResponseWithNoHeaderTerminator() =
        runTest {
            val mock = MockDuplex(listOf(utf8("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n")))
            val ex = assertFails { streamFetch("http://localhost/", StreamFetchInit(mock)) }
            assertTrue(
                ex.message?.contains("Unexpected end", ignoreCase = true) == true ||
                    ex.message?.contains("header", ignoreCase = true) == true,
            )
        }

    @Test
    fun abortsWhileWaitingForResponse() =
        runTest {
            val stream =
                object : ByteDuplex {
                    override suspend fun read(n: Int): ByteArray {
                        kotlinx.coroutines.CompletableDeferred<ByteArray>().await()
                        return ByteArray(0)
                    }

                    override suspend fun write(bytes: ByteArray) {}

                    override fun close() {}
                }
            val ac = Abort()
            supervisorScope {
                val pending =
                    async {
                        streamFetch("http://localhost/", StreamFetchInit(stream, abort = ac))
                    }
                ac.abort(Exception("aborted"))
                val ex = runCatching { pending.await() }.exceptionOrNull()
                assertTrue(ex != null && ex.message?.contains("aborted") == true)
            }
        }
}
