package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.posix.SEEK_END
import platform.posix.SEEK_SET
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.fseek
import platform.posix.ftell

@OptIn(ExperimentalForeignApi::class)
internal actual fun readTestFixture(path: String): ByteArray {
    val full = "$TEST_FIXTURE_DIR/$path"
    val file = fopen(full, "rb") ?: error("cannot open $full")
    try {
        fseek(file, 0, SEEK_END)
        val size = ftell(file).toInt()
        fseek(file, 0, SEEK_SET)
        val out = ByteArray(size)
        if (size > 0) {
            val read = out.usePinned { fread(it.addressOf(0), 1.convert(), size.convert(), file) }
            check(read.toInt() == size) { "short read of $full" }
        }
        return out
    } finally {
        fclose(file)
    }
}
