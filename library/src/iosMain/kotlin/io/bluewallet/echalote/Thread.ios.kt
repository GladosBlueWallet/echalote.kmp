package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSThread
import platform.posix.pthread_mach_thread_np
import platform.posix.pthread_self

/** "main" or "t<mach thread id>", so timing logs can tell worker threads apart. */
@OptIn(ExperimentalForeignApi::class)
internal actual fun currentThreadName(): String = if (NSThread.isMainThread) "main" else "t${pthread_mach_thread_np(pthread_self())}"
