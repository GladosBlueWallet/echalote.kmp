package org.hazae41.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import platform.posix.O_RDONLY
import platform.posix.close
import platform.posix.gettimeofday
import platform.posix.open
import platform.posix.read
import platform.posix.timeval

@OptIn(ExperimentalForeignApi::class)
internal actual fun fillSecureRandom(bytes: ByteArray) {
    if (bytes.isEmpty()) return
    val fd = open("/dev/urandom", O_RDONLY)
    check(fd >= 0) { "cannot open /dev/urandom" }
    try {
        bytes.usePinned { pinned ->
            var off = 0
            while (off < bytes.size) {
                val n = read(fd, pinned.addressOf(off), (bytes.size - off).convert())
                check(n > 0) { "short read from /dev/urandom" }
                off += n.toInt()
            }
        }
    } finally {
        close(fd)
    }
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun currentEpochMillis(): Long = memScoped {
    val tv = alloc<timeval>()
    gettimeofday(tv.ptr, null)
    tv.tv_sec * 1000L + tv.tv_usec / 1000L
}
