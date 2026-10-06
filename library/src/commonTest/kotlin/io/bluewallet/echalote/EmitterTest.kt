package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class EmitterTest {
    /** `@Volatile` is field-only; the brief's local annotation does not compile. */
    private class FailureSlot {
        @Volatile var value: Throwable? = null
    }

    @Test
    fun emitCallsEveryCurrentListener() {
        val emitter = Emitter<Int>()
        val seen = mutableListOf<Int>()
        emitter.on { seen += it }
        emitter.on { seen += it * 10 }
        emitter.emit(3)
        assertEquals(listOf(3, 30), seen)
    }

    @Test
    fun unsubscribeDropsOnlyThatListener() {
        val emitter = Emitter<String>()
        val seen = mutableListOf<String>()
        val off = emitter.on { seen += "a:$it" }
        emitter.on { seen += "b:$it" }
        off()
        off()
        emitter.emit("x")
        assertEquals(listOf("b:x"), seen)
    }

    @Test
    fun throwingListenerDoesNotStopTheRest() {
        val emitter = Emitter<Int>()
        val seen = mutableListOf<Int>()
        emitter.on { throw IllegalStateException("boom") }
        emitter.on { seen += it }
        emitter.emit(7)
        assertEquals(listOf(7), seen)
    }

    @Test
    fun emitDoesNotCrashWhileListenersComeAndGo() =
        runBlocking {
            val emitter = Emitter<Int>()
            val failed = FailureSlot()
            val jobs =
                List(8) { worker ->
                    launch(Dispatchers.Default) {
                        repeat(20_000) { i ->
                            try {
                                val off = emitter.on { }
                                emitter.emit(worker * 1_000_000 + i)
                                off()
                            } catch (err: Throwable) {
                                if (failed.value == null) failed.value = err
                            }
                        }
                    }
                }
            jobs.forEach { it.join() }
            assertNull(failed.value, failed.value?.stackTraceToString())
        }
}
