package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpEngineCancelTest {
    /** A cancelled request must release its thread now, not when the 30 s socket timeout fires. */
    @Test
    fun cancellingABlockedRequestReturnsPromptly() =
        runBlocking {
            ServerSocket(0).use { server ->
                val accepted = ArrayList<java.net.Socket>()
                val acceptor = Thread { runCatching { accepted += server.accept() } }.apply { start() }
                val started = System.nanoTime()
                val res =
                    withTimeoutOrNull(300) {
                        defaultHttpEngine().call("GET", "http://127.0.0.1:${server.localPort}/slow", timeoutMs = 30_000)
                    }
                val elapsedMs = (System.nanoTime() - started) / 1_000_000
                assertNull(res)
                assertTrue(elapsedMs < 3_000, "took $elapsedMs ms")
                acceptor.join(1_000)
                val peer = accepted.single()
                peer.soTimeout = 2_000
                // The client side was closed on cancel: the server sees EOF (or a reset), not silence.
                val eof = runCatching { peer.getInputStream().readAllBytes() }
                assertTrue(eof.isSuccess || eof.exceptionOrNull() !is java.net.SocketTimeoutException, "client socket left open: $eof")
                peer.close()
            }
        }
}
