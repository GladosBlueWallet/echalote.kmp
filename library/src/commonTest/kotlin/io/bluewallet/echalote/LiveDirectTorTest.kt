package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeSource

/**
 * Live direct relay mode on every platform with sockets (JVM, Android host, iOS simulator).
 * Skipped unless ECHALOTE_LIVE_DIRECT=1 (on the iOS simulator the variable reaches the test
 * process as SIMCTL_CHILD_ECHALOTE_LIVE_DIRECT; see library/build.gradle.kts).
 *
 * No mocks: it connects over this platform's TCP transport straight to a real guard relay's
 * ORPort, builds a real 3-hop circuit, and fetches https://api.rocketx.exchange/v1/configs with
 * full TLS certificate verification. It then switches direct mode off at runtime and fetches
 * again, which must go through the meek bridge.
 */
class LiveDirectTorTest {
    @Test
    fun live_direct_tor_rocketx_fetchVerifies() =
        runTest(timeout = 8.minutes) {
            if (testEnv("ECHALOTE_LIVE_DIRECT") != "1") return@runTest
            withContext(Dispatchers.Default) {
                Echalote.resetConnections()
                resetTlsSessionCache()
                lastBootstrapRoute = null
                lastDirectGuard = null
                try {
                    Echalote.setDirectRelay(true)
                    val started = TimeSource.Monotonic.markNow()
                    val res = Echalote.fetch(URL, Abort())
                    val ms = started.elapsedNow().inWholeMilliseconds
                    val route = lastBootstrapRoute
                    println(
                        "live direct tor api.rocketx.exchange -> route=$route guard=$lastDirectGuard " +
                            "status=${res.status} bytes=${res.body.size} in ${ms}ms",
                    )
                    // DIRECT is recorded only after the TCP connection to the guard's ORPort and the
                    // Tor link handshake (which checks the guard's identity key) both succeeded; a
                    // fallback to the meek bridge records MEEK instead.
                    assertEquals(TorRoute.DIRECT, route, "direct mode fell back to meek")
                    assertTrue(res.status in 200..499, "status ${res.status}")
                    assertTrue(res.body.isNotEmpty(), "empty body")

                    // Runtime switch off: the next request must reconnect through the bridge.
                    Echalote.setDirectRelay(false)
                    lastBootstrapRoute = null
                    val offStarted = TimeSource.Monotonic.markNow()
                    val off = Echalote.fetch(URL, Abort())
                    val offMs = offStarted.elapsedNow().inWholeMilliseconds
                    println(
                        "live direct-off tor api.rocketx.exchange -> route=$lastBootstrapRoute " +
                            "status=${off.status} bytes=${off.body.size} in ${offMs}ms",
                    )
                    assertEquals(TorRoute.MEEK, lastBootstrapRoute, "switching direct mode off did not reconnect via meek")
                    assertTrue(off.status in 200..499, "status ${off.status}")
                } finally {
                    Echalote.setDirectRelay(false)
                    Echalote.resetConnections()
                }
            }
        }

    private companion object {
        const val URL = "https://api.rocketx.exchange/v1/configs"
    }
}
