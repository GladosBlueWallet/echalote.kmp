@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.bluewallet.echalote

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlin.concurrent.atomics.AtomicInt

/**
 * Lets a blocking HTTP call be interrupted from another thread. The call registers how to
 * interrupt itself (close the socket, disconnect the connection) and releases its resources
 * through [release]; the lock makes sure an interrupt never touches a released resource.
 */
internal class CancelHook {
    private val lock = AtomicInt(0)
    private var action: (() -> Unit)? = null
    private var cancelled = false

    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) {
            // Held only for a syscall or two.
        }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    /** True once [cancel] ran; blocking code that waits in slices polls this between them. */
    val isCancelled: Boolean get() = locked { cancelled }

    fun register(onCancel: () -> Unit) =
        locked {
            action = onCancel
            if (cancelled) onCancel()
        }

    fun release(close: () -> Unit = {}) =
        locked {
            action = null
            close()
        }

    fun cancel() =
        locked {
            cancelled = true
            action?.invoke()
            action = null
        }
}

/**
 * Runs blocking [block] on [dispatcher]. If the calling coroutine is cancelled, the hook's
 * registered interrupt runs so the blocked thread is released, and this returns at once
 * without waiting for that thread (its late failure is dropped).
 */
internal suspend fun <T> cancellableBlocking(
    dispatcher: CoroutineDispatcher,
    block: (CancelHook) -> T,
): T {
    val hook = CancelHook()
    val work = CoroutineScope(dispatcher).async { block(hook) }
    try {
        return work.await()
    } catch (e: kotlinx.coroutines.CancellationException) {
        hook.cancel()
        work.cancel()
        throw e
    }
}
