package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Live checks against real servers. Skipped unless enabled:
 *  ECHALOTE_LIVE_TLS=1  direct TCP to api.rocketx.exchange and badssl.com (no Tor)
 *  ECHALOTE_LIVE_TOR=1  Echalote.fetch to api.rocketx.exchange over a real Tor circuit
 */
class LiveTlsSmokeTest {
    private fun enabled(name: String) = System.getenv(name) == "1"

    private fun direct(
        host: String,
        sni: String = host,
    ): String =
        runBlocking {
            val transport = SocketDuplex(Socket(host, 443))
            try {
                val tls = wrapTls(transport, sni, Abort())
                try {
                    httpGetOver(tls, sni, "/v1/configs")
                } finally {
                    tls.close()
                }
            } finally {
                transport.close()
            }
        }

    @Test
    fun live_direct_rocketx_chainVerifies() {
        if (!enabled("ECHALOTE_LIVE_TLS")) return
        resetTlsSessionCache()
        val res = direct("api.rocketx.exchange")
        println("live direct api.rocketx.exchange -> ${res.lineSequence().first()}")
        assertTrue(res.startsWith("HTTP/1.1 "), res)
    }

    @Test
    fun live_direct_badssl_isRejected() {
        if (!enabled("ECHALOTE_LIVE_TLS")) return
        for (host in listOf("self-signed.badssl.com", "wrong.host.badssl.com", "expired.badssl.com", "untrusted-root.badssl.com")) {
            val err = assertFailsWith<TlsCertificateError>(host) { direct(host) }
            println("live direct $host -> rejected: ${err.message}")
        }
    }

    @Test
    fun live_tor_rocketx_fetchVerifies() {
        if (!enabled("ECHALOTE_LIVE_TOR")) return
        resetTlsSessionCache()
        val started = System.nanoTime()
        val res = runBlocking { Echalote.fetch("https://api.rocketx.exchange/v1/configs", Abort()) }
        val ms = (System.nanoTime() - started) / 1_000_000
        println("live tor api.rocketx.exchange -> status=${res.status} bytes=${res.body.size} in ${ms}ms")
        assertTrue(res.status in 200..499, "status ${res.status}")
    }
}
