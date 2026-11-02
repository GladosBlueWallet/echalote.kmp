package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Switching direct relay mode at runtime (no network: dialers are never asked to dial live). */
class DirectRelaySwitchTest {
    private class FakeStream : ByteDuplex {
        var closed = false

        override suspend fun read(n: Int): ByteArray = ByteArray(0)

        override suspend fun write(bytes: ByteArray) = Unit

        override fun close() {
            closed = true
        }
    }

    @BeforeTest
    fun clean() =
        runTest {
            Echalote.resetConnections()
            Echalote.directRelay = false
        }

    @AfterTest
    fun restore() =
        runTest {
            Echalote.resetConnections()
            Echalote.directRelay = false
            httpsSessionFactory = null
        }

    /** A disposed exit dialer refuses to dial instead of bootstrapping again. */
    private suspend fun assertDisposed(dialer: ExitDialer) {
        val err = assertFailsWith<Exception> { dialer.dial("example.com", 443) }
        assertTrue(err.message.orEmpty().contains("disposed"), err.message)
    }

    @Test
    fun turningDirectOnReplacesTheLiveConnection() =
        runTest {
            val meek = defaultExitDialer()
            assertEquals(false, defaultDialerDirectMode())
            Echalote.setDirectRelay(true)
            assertTrue(Echalote.directRelay)
            assertNull(defaultDialerDirectMode(), "old dialer must be dropped right away")
            assertDisposed(meek)
            val direct = defaultExitDialer()
            assertNotSame(meek, direct)
            assertEquals(true, defaultDialerDirectMode())
        }

    @Test
    fun turningDirectOffReplacesTheLiveConnection() =
        runTest {
            Echalote.setDirectRelay(true)
            val direct = defaultExitDialer()
            assertEquals(true, defaultDialerDirectMode())
            Echalote.setDirectRelay(false)
            assertFalse(Echalote.directRelay)
            assertDisposed(direct)
            defaultExitDialer()
            assertEquals(false, defaultDialerDirectMode())
        }

    @Test
    fun settingTheSameModeKeepsTheConnection() =
        runTest {
            val first = defaultExitDialer()
            Echalote.setDirectRelay(false)
            assertSame(first, defaultExitDialer())
        }

    @Test
    fun propertySetterAppliesToTheNextNewConnection() =
        runTest {
            val meek = defaultExitDialer()
            Echalote.directRelay = true
            val next = defaultExitDialer()
            assertNotSame(meek, next)
            assertEquals(true, defaultDialerDirectMode())
            assertDisposed(meek)
        }

    @Test
    fun setDirectRelayAfterPropertySetterStillDropsSessions() =
        runTest {
            // The flag already says direct, but the live dialer and sessions are still meek.
            defaultExitDialer()
            Echalote.directRelay = true
            val stream = FakeStream()
            httpsSessionFactory = { _, _, _ -> HttpsSession(stream) { stream.close() } }
            warmUpHttps("https://example.com/")
            Echalote.setDirectRelay(true)
            assertTrue(stream.closed, "kept-alive session on the old route must be closed")
            assertNull(defaultDialerDirectMode())
        }

    @Test
    fun switchClosesKeptAliveHttpsSessions() =
        runTest {
            val stream = FakeStream()
            var opens = 0
            httpsSessionFactory = { _, _, _ ->
                opens++
                HttpsSession(stream) { stream.close() }
            }
            warmUpHttps("https://example.com/")
            assertEquals(1, opens)
            assertFalse(stream.closed)
            Echalote.setDirectRelay(true)
            assertTrue(stream.closed)
            warmUpHttps("https://example.com/")
            assertEquals(2, opens, "next request must open a fresh session")
        }

    @Test
    fun resetConnectionsDropsDialerAndSessions() =
        runTest {
            val stream = FakeStream()
            httpsSessionFactory = { _, _, _ -> HttpsSession(stream) { stream.close() } }
            val dialer = defaultExitDialer()
            warmUpHttps("https://example.com/")
            Echalote.resetConnections()
            assertTrue(stream.closed)
            assertDisposed(dialer)
            assertNull(defaultDialerDirectMode())
        }
}
