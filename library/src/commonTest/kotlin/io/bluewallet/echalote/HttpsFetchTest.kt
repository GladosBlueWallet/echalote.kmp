package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HttpsFetchTest {
    private class ScriptedDuplex(
        private val responses: List<ByteArray>,
    ) : ByteDuplex {
        val writes = ArrayList<String>()
        private var idx = 0
        var closed = false

        override suspend fun read(n: Int): ByteArray {
            if (idx >= responses.size) return ByteArray(0)
            return responses[idx++]
        }

        override suspend fun write(bytes: ByteArray) {
            writes += bytes.decodeToString()
        }

        override fun close() {
            closed = true
        }
    }

    @Test
    fun retriesEmptyGetOnSameSession() =
        runTest {
            val body = """{"IsTor":true,"IP":"1.2.3.4"}"""
            val payload = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body".encodeToByteArray()
            val stream = ScriptedDuplex(listOf(ByteArray(0), payload))
            var opens = 0
            httpsSessionFactory = { _, _, _ ->
                opens++
                HttpsSession(stream) { stream.close() }
            }
            try {
                resetHttpsSessions()
                val res = httpsFetch("https://check.torproject.org/api/ip")
                assertEquals(200, res.status)
                assertEquals(1, opens)
                assertEquals(2, stream.writes.size)
            } finally {
                resetHttpsSessions()
                httpsSessionFactory = null
            }
        }

    @Test
    fun reusesOpenSessionForSecondGet() =
        runTest {
            val body = """{"IsTor":true,"IP":"1.2.3.4"}"""
            val payload =
                "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: keep-alive\r\n\r\n$body"
                    .encodeToByteArray()
            val stream = ScriptedDuplex(listOf(payload, payload))
            var opens = 0
            httpsSessionFactory = { _, _, _ ->
                opens++
                HttpsSession(stream) { stream.close() }
            }
            try {
                resetHttpsSessions()
                val a = httpsFetch("https://check.torproject.org/api/ip")
                val b = httpsFetch("https://check.torproject.org/api/ip")
                assertEquals(200, a.status)
                assertEquals(200, b.status)
                assertEquals(1, opens)
                assertEquals(2, stream.writes.size)
                assertTrue(stream.writes[0].contains("Connection: keep-alive"))
                assertEquals(false, stream.closed)
            } finally {
                resetHttpsSessions()
                httpsSessionFactory = null
            }
        }

    @Test
    fun postsOnReusedSession() =
        runTest {
            val getBody = """{"ok":true}"""
            val postBody = """{"id":1}"""
            val getPayload =
                "HTTP/1.1 200 OK\r\nContent-Length: ${getBody.length}\r\nConnection: keep-alive\r\n\r\n$getBody"
                    .encodeToByteArray()
            val postPayload =
                "HTTP/1.1 200 OK\r\nContent-Length: ${postBody.length}\r\nConnection: keep-alive\r\n\r\n$postBody"
                    .encodeToByteArray()
            val stream = ScriptedDuplex(listOf(getPayload, postPayload))
            var opens = 0
            httpsSessionFactory = { _, _, _ ->
                opens++
                HttpsSession(stream) { stream.close() }
            }
            try {
                resetHttpsSessions()
                val get = httpsFetch("https://api.rocketx.exchange/v1/configs")
                val payload = """{"a":1}""".encodeToByteArray()
                val post =
                    httpsFetch(
                        "https://api.rocketx.exchange/v1/quote",
                        method = "POST",
                        headers = mapOf("Content-Type" to "application/json"),
                        body = payload,
                    )
                assertEquals(200, get.status)
                assertEquals(200, post.status)
                assertEquals(1, opens)
                assertTrue(stream.writes[0].startsWith("GET /v1/configs HTTP/1.1"))
                assertTrue(stream.writes[1].startsWith("POST /v1/quote HTTP/1.1"))
                assertTrue(stream.writes[1].contains("{\"a\":1}"))
            } finally {
                resetHttpsSessions()
                httpsSessionFactory = null
            }
        }

    @Test
    fun reportsMonotonicProgressAndFinishesAt100() =
        runTest {
            val body = "x".repeat(80)
            val header = "HTTP/1.1 200 OK\r\nContent-Length: 80\r\nConnection: keep-alive\r\n\r\n"
            val stream =
                ScriptedDuplex(
                    listOf(
                        (header + body.substring(0, 30)).encodeToByteArray(),
                        body.substring(30).encodeToByteArray(),
                    ),
                )
            httpsSessionFactory = { _, _, _ -> HttpsSession(stream) { stream.close() } }
            val events = ArrayList<Pair<Int, String>>()
            try {
                resetHttpsSessions()
                val res =
                    httpsFetch("https://example.com/data") { percent, stage ->
                        events += percent to stage
                    }
                assertEquals(200, res.status)
            } finally {
                resetHttpsSessions()
                httpsSessionFactory = null
            }
            assertTrue(events.isNotEmpty())
            assertEquals(0, events.first().first)
            assertEquals("Starting", events.first().second)
            assertTrue(events.any { it.second == "Sending request" })
            val downloads = events.filter { it.second == "Downloading response" }
            assertTrue(downloads.size >= 2, "expected incremental download ticks, got $events")
            assertTrue(downloads.first().first < downloads.last().first)
            assertEquals(100, events.last().first)
            assertEquals("Done", events.last().second)
            assertTrue(events.zipWithNext().all { it.first.first <= it.second.first })
        }
}
