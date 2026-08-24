package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertEquals

class Http1Test {
    @Test
    fun parseHttpUrl_host_port_path() {
        val u = parseHttpUrl("http://217.196.147.77:80/tor/status-vote/current/consensus-microdesc")
        assertEquals("217.196.147.77", u.host)
        assertEquals(80, u.port)
        assertEquals("/tor/status-vote/current/consensus-microdesc", u.path)
    }

    @Test
    fun parseHttp1Response_http10_without_content_length_keeps_body() {
        val raw = (
            "HTTP/1.0 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "Content-Encoding: identity\r\n" +
                "\r\n" +
                "network-status-version 3 microdesc\n" +
                "directory-footer\n"
            ).encodeToByteArray()
        val res = parseHttp1Response(raw)
        assertEquals(200, res.status)
        assertEquals(
            "network-status-version 3 microdesc\ndirectory-footer\n",
            res.body.decodeToString(),
        )
    }

    @Test
    fun parseHttp1Response_respects_content_length() {
        val raw = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 5\r\n" +
                "\r\n" +
                "helloTRAILING"
            ).encodeToByteArray()
        val res = parseHttp1Response(raw)
        assertEquals(200, res.status)
        assertEquals("hello", res.body.decodeToString())
    }

    @Test
    fun http1MessageComplete_needs_content_length_and_full_body() {
        val prefix = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".encodeToByteArray()
        assertEquals(false, http1MessageComplete("HTTP/1.1 200 OK\r\n".encodeToByteArray()))
        assertEquals(false, http1MessageComplete(prefix + "hel".encodeToByteArray()))
        assertEquals(true, http1MessageComplete(prefix + "hello".encodeToByteArray()))
        assertEquals(true, http1MessageComplete(prefix + "helloTRAILING".encodeToByteArray()))
        assertEquals(
            false,
            http1MessageComplete("HTTP/1.0 200 OK\r\n\r\nbody".encodeToByteArray()),
        )
    }

    @Test
    fun readHttp1Raw_stops_at_content_length_without_waiting_for_eof() {
        val chunks = ArrayDeque(
            listOf(
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe".encodeToByteArray(),
                "llo".encodeToByteArray(),
                "SHOULD_NOT_READ".encodeToByteArray(),
            ),
        )
        val raw = readHttp1Raw { chunks.removeFirstOrNull() }
        assertEquals("hello", parseHttp1Response(raw).body.decodeToString())
        assertEquals(1, chunks.size)
    }

    @Test
    fun readHttp1Raw_without_content_length_reads_until_eof() {
        val chunks = ArrayDeque(
            listOf(
                "HTTP/1.0 200 OK\r\n\r\nnet".encodeToByteArray(),
                "work".encodeToByteArray(),
            ),
        )
        val raw = readHttp1Raw { chunks.removeFirstOrNull() }
        assertEquals("network", parseHttp1Response(raw).body.decodeToString())
    }

    @Test
    fun readHttp1Raw_truncated_content_length_fails() {
        val chunks = ArrayDeque(
            listOf("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe".encodeToByteArray()),
        )
        val err = runCatching { readHttp1Raw { chunks.removeFirstOrNull() } }.exceptionOrNull()
        assertEquals(true, err is IllegalArgumentException)
    }
}
