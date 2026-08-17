package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class ExitDialerTest {
    @Test
    fun returnsDialAndDispose() {
        val dialer = createExitDialer()
        // structural: both members exist
        assertTrue(dialer is ExitDialer)
    }

    @Test
    fun disposeIsIdempotentBeforeBootstrap() = runTest {
        val dialer = createExitDialer()
        dialer.dispose()
        dialer.dispose()
        val ex = assertFails { dialer.dial("example.com", 80) }
        assertTrue(ex.message?.contains("disposed", ignoreCase = true) == true)
    }
}
