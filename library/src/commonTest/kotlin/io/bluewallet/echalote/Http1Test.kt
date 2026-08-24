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
}
