package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class ClearnetParallelTest {
    @Test
    fun returnsFirstSuccessfulResultAndCancelsSlowerWork() = runTest {
        val started = ArrayList<String>()
        val cancelled = ArrayList<String>()
        val result = fetchFirstOk(
            listOf("slow", "fast", "also-slow"),
            worker = { key, signal ->
                started += key
                if (key == "fast") return@fetchFirstOk "ok:$key"
                val done = CompletableDeferred<Unit>()
                signal.onAbort {
                    cancelled += key
                    done.completeExceptionally(signal.reason ?: Exception("aborted"))
                }
                delay(100)
                "ok:$key"
            },
            concurrency = 3,
        )
        assertEquals("ok:fast", result)
        assertEquals(3, started.size)
        delay(20)
        assertTrue(cancelled.isNotEmpty())
    }

    @Test
    fun triesUntilOneSucceedsWithinConcurrency() = runTest {
        var n = 0
        val result = fetchFirstOk(
            listOf("a", "b", "c"),
            worker = { key, _ ->
                n++
                if (key != "c") throw Exception("fail $key")
                key
            },
            concurrency = 2,
        )
        assertEquals("c", result)
        assertEquals(3, n)
    }

    @Test
    fun rejectsAggregateErrorWhenEveryWorkerFails() = runTest {
        val ex = assertFails {
            fetchFirstOk(
                listOf("a", "b"),
                worker = { key, _ -> throw Exception("fail $key") },
                concurrency = 2,
            )
        }
        assertTrue(ex is AggregateError || ex.message?.contains("fetchFirstOk", ignoreCase = true) == true)
        assertTrue(ex.message?.contains("fetchFirstOk", ignoreCase = true) == true)
        assertTrue(ex.message!!.contains("fail a"), ex.message)
        assertTrue(ex.message!!.contains("fail b"), ex.message)
    }

    @Test
    fun rejectsOnParentAbortEvenIfWorkerIgnoresSignal() = runTest {
        val parent = Abort()
        supervisorScope {
            val pending = async {
                fetchFirstOk(
                    listOf("hang"),
                    worker = { _, _ ->
                        CompletableDeferred<String>().await()
                    },
                    concurrency = 1,
                    signal = parent,
                )
            }
            parent.abort(Exception("parent cancelled"))
            val ex = runCatching { pending.await() }.exceptionOrNull()
            assertTrue(ex != null && ex.message?.contains("parent cancelled") == true)
        }
    }
}
