package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TlsSessionResumeTest {
    @Test
    fun parseNewSessionTicket_readsLifetimeAndBytes() {
        val ticket = byteArrayOf(1, 2, 3, 4, 5)
        val body = ByteArray(6 + ticket.size)
        body.putU32be(0, 3600)
        body.putU16be(4, ticket.size)
        ticket.copyInto(body, 6)
        val parsed = parseNewSessionTicket(body)
        assertEquals(3600L, parsed.lifetimeHintSec)
        assertTrue(parsed.ticket.contentEquals(ticket))
    }

    @Test
    fun sessionCache_isPerHostAndExpires() {
        resetTlsSessionCache()
        val master = ByteArray(48) { 7 }
        val ticket = byteArrayOf(9, 8, 7)
        rememberTlsSession(
            TlsResumption(
                host = "Api.Example.com",
                master = master,
                sessionId = ByteArray(0),
                ticket = ticket,
                ems = true,
                expiresAtMs = 10_000,
            ),
        )
        val hit = lookupTlsSession("api.example.com", nowMs = 9_999)
        requireNotNull(hit)
        assertTrue(hit.master.contentEquals(master))
        assertTrue(hit.ticket.contentEquals(ticket))
        assertTrue(hit.ems)
        assertNull(lookupTlsSession("other.example", nowMs = 9_999))
        assertNull(lookupTlsSession("api.example.com", nowMs = 10_000))
        resetTlsSessionCache()
    }

    @Test
    fun clientHello_offersEmptySessionTicket() =
        runTest {
            resetTlsSessionCache()
            val tls = TlsClientDuplex("check.torproject.org")
            try {
                val rec = tls.inner.read(16 * 1024)
                assertTrue(clientHelloHasExtension(rec, 0x0023))
            } finally {
                tls.close()
                resetTlsSessionCache()
            }
        }

    @Test
    fun clientHello_sendsCachedTicket() =
        runTest {
            resetTlsSessionCache()
            val ticket = "ticket-bytes-xyz".encodeToByteArray()
            rememberTlsSession(
                TlsResumption(
                    host = "check.torproject.org",
                    master = ByteArray(48) { 1 },
                    sessionId = ByteArray(0),
                    ticket = ticket,
                    ems = true,
                    expiresAtMs = Long.MAX_VALUE,
                ),
            )
            val tls = TlsClientDuplex("check.torproject.org")
            try {
                val rec = tls.inner.read(16 * 1024)
                assertTrue(indexOfBytes(rec, ticket) >= 0)
            } finally {
                tls.close()
                resetTlsSessionCache()
            }
        }

    private fun clientHelloHasExtension(
        record: ByteArray,
        type: Int,
    ): Boolean {
        require(record.size > 9 && record[0] == 22.toByte())
        val hs = record.copyOfRange(5, record.size)
        require(hs[0] == 1.toByte())
        val bodyLen = (hs.u8(1) shl 16) or hs.u16be(2)
        val body = hs.copyOfRange(4, 4 + bodyLen)
        var o = 34
        o += 1 + body.u8(o)
        val csLen = body.u16be(o)
        o += 2 + csLen
        o += 1 + body.u8(o)
        var found = false
        if (o + 2 <= body.size) {
            val extLen = body.u16be(o)
            o += 2
            val end = o + extLen
            while (o + 4 <= end) {
                val et = body.u16be(o)
                val el = body.u16be(o + 2)
                o += 4
                if (et == type) found = true
                o += el
            }
        }
        return found
    }

    private fun indexOfBytes(
        haystack: ByteArray,
        needle: ByteArray,
    ): Int {
        val max = haystack.size - needle.size
        var found = -1
        var i = 0
        while (needle.isNotEmpty() && i <= max && found < 0) {
            if (haystack.copyOfRange(i, i + needle.size).contentEquals(needle)) found = i
            i++
        }
        return found
    }
}
