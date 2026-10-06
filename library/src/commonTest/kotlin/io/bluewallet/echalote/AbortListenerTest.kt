package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AbortListenerTest {
    /** `@Volatile` is field-only; the brief's local annotation does not compile. */
    private class FailureSlot {
        @Volatile var value: Throwable? = null
    }

    @Test
    fun abortRunsListenersThenIgnoresLaterSubscribers() {
        val abort = Abort()
        var runs = 0
        abort.onAbort { runs += 1 }
        abort.abort()
        abort.onAbort { runs += 10 }
        assertEquals(11, runs)
        assertTrue(abort.aborted)
    }

    @Test
    fun throwingAbortListenerDoesNotStopTheRest() {
        val abort = Abort()
        var ran = false
        abort.onAbort { throw IllegalStateException("boom") }
        abort.onAbort { ran = true }
        abort.abort()
        assertTrue(ran)
    }

    @Test
    fun subscribeDuringAbortDoesNotCrash() =
        runBlocking {
            val abort = Abort()
            val failed = FailureSlot()
            val jobs =
                List(8) {
                    launch(Dispatchers.Default) {
                        repeat(4_000) {
                            try {
                                abort.onAbort { }
                            } catch (err: Throwable) {
                                if (failed.value == null) failed.value = err
                            }
                        }
                    }
                }
            launch(Dispatchers.Default) {
                repeat(200) {
                    try {
                        abort.abort()
                    } catch (err: Throwable) {
                        if (failed.value == null) failed.value = err
                    }
                }
            }.join()
            jobs.forEach { it.join() }
            assertNull(failed.value, failed.value?.stackTraceToString())
        }
}
