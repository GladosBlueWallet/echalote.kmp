package org.hazae41.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** AbortSignal analogue for races and timeouts. */
class Abort {
    var aborted: Boolean = false
        private set
    var reason: Throwable? = null
        private set
    private val listeners = ArrayList<() -> Unit>()

    fun abort(cause: Throwable = CancellationException("aborted")) {
        if (aborted) return
        aborted = true
        reason = cause
        val copy = listeners.toList()
        listeners.clear()
        for (l in copy) {
            try {
                l()
            } catch (_: Throwable) {
            }
        }
    }

    fun onAbort(block: () -> Unit) {
        if (aborted) block() else listeners += block
    }

    fun throwIfAborted() {
        if (aborted) throw reason ?: CancellationException("aborted")
    }

    companion object {
        fun timeout(ms: Long): Abort {
            val a = Abort()
            // Caller should abort via coroutine delay; this helper is for tests that
            // construct a signal they abort themselves.
            a.also { it.hashCode() }
            return a
        }

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

open class CancellationException(message: String, cause: Throwable? = null) : Exception(message, cause)

internal suspend fun <T> withAbort(abort: Abort?, block: suspend () -> T): T {
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

internal suspend fun <T> withAbortTimeout(ms: Long, parent: Abort?, block: suspend (Abort) -> T): T {
    val timeout = Abort()
    val linked = if (parent != null) Abort.any(parent, timeout) else timeout
    return coroutineScope {
        val timer = launch {
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
