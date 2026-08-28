package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertTrue

class TlsClientHelloTest {
    @Test
    fun clientHello_includes_sni_when_host_is_set() = runTest {
        val tls = TlsClientDuplex("check.torproject.org")
        try {
            val rec = tls.inner.read(16 * 1024)
            val host = "check.torproject.org".encodeToByteArray()
            assertTrue(indexOfBytes(rec, host) >= 0)
        } finally {
            tls.close()
        }
    }

    @Test
    fun clientHello_omits_sni_when_host_is_absent() = runTest {
        val tls = TlsClientDuplex()
        try {
            val rec = tls.inner.read(16 * 1024)
            val host = "check.torproject.org".encodeToByteArray()
            assertTrue(indexOfBytes(rec, host) < 0)
        } finally {
            tls.close()
        }
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
