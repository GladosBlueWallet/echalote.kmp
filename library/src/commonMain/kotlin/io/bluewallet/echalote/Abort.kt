@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.bluewallet.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile

/** AbortSignal analogue for races and timeouts. */
class Abort {
    @Volatile
    var aborted: Boolean = false
        private set

    @Volatile
    var reason: Throwable? = null
        private set

    private val listeners = kotlin.concurrent.atomics.AtomicReference(emptyList<() -> Unit>())

    fun abort(cause: Throwable = CancellationException("aborted")) {
        if (aborted) return
        aborted = true
        reason = cause
        val copy = listeners.exchange(emptyList())
        for (l in copy) {
            try {
                l()
            } catch (_: Throwable) {
            }
        }
    }

    fun onAbort(block: () -> Unit) {
        var added = false
        while (!aborted && !added) {
            val current = listeners.load()
            added = listeners.compareAndSet(current, current + block)
        }
        if (aborted) {
            if (!added) {
                block()
            } else {
                claimAndRun(block)
            }
        }
    }

    private fun claimAndRun(block: () -> Unit) {
        var claimed = false
        while (!claimed) {
            val published = listeners.load()
            val index = published.indexOfFirst { it === block }
            if (index < 0) return
            claimed =
                listeners.compareAndSet(
                    published,
                    published.filterIndexed { i, _ -> i != index },
                )
        }
        block()
    }

    fun throwIfAborted() {
        if (aborted) throw reason ?: CancellationException("aborted")
    }

    companion object {
        fun timeout(
            @Suppress("UnusedParameter") ms: Long,
        ): Abort = Abort()

        fun any(vararg signals: Abort): Abort {
            val out = Abort()
            for (s in signals) {
                s.onAbort {
                    out.abort(s.reason ?: CancellationException("aborted"))
                }
            }
            return out
        }
    }
}

open class CancellationException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

internal suspend fun <T> withAbort(
    abort: Abort?,
    block: suspend () -> T,
): T {
    abort?.throwIfAborted()
    if (abort == null) return block()
    return coroutineScope {
        val job = async { block() }
        abort.onAbort { job.cancel() }
        try {
            job.await()
        } catch (e: kotlinx.coroutines.CancellationException) {
            abort.throwIfAborted()
            throw e
        }
    }
}

internal suspend fun <T> withAbortTimeout(
    ms: Long,
    parent: Abort?,
    block: suspend (Abort) -> T,
): T {
    val timeout = Abort()
    val linked = if (parent != null) Abort.any(parent, timeout) else timeout
    return coroutineScope {
        val timer =
            launch {
                delay(ms)
                timeout.abort(Exception("The operation timed out."))
            }
        try {
            withAbort(linked) { block(linked) }
        } finally {
            timer.cancel()
        }
    }
}
