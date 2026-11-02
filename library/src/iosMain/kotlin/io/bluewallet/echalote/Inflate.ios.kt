package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import platform.zlib.Z_BUF_ERROR
import platform.zlib.Z_NO_FLUSH
import platform.zlib.Z_OK
import platform.zlib.Z_STREAM_END
import platform.zlib.inflate
import platform.zlib.inflateEnd
import platform.zlib.inflateInit2_
import platform.zlib.z_stream
import platform.zlib.zlibVersion

/*
 * Apple's system libz instead of the pure-Kotlin InflateKt, which took ~1 s per consensus copy
 * on the CI simulator. Same contract as the JVM version: whole-buffer decode, checksum checked
 * by zlib, MAX_HTTP1_BODY cap, null on anything malformed or truncated.
 */

internal actual fun inflateZlibOrNull(input: ByteArray): ByteArray? {
    if (input.size < 2 || (input[0].toInt() and 0xff) != 0x78) return null
    return systemInflate(input, windowBits = 15)
}

internal actual fun inflateGzipOrNull(input: ByteArray): ByteArray? {
    if (input.size < 18 || (input[0].toInt() and 0xff) != 0x1f || (input[1].toInt() and 0xff) != 0x8b) return null
    return systemInflate(input, windowBits = 16 + 15)
}

@OptIn(ExperimentalForeignApi::class)
private fun systemInflate(
    input: ByteArray,
    windowBits: Int,
): ByteArray? =
    memScoped {
        val strm = alloc<z_stream>()
        strm.zalloc = null
        strm.zfree = null
        strm.opaque = null
        strm.avail_in = 0u
        strm.next_in = null
        if (inflateInit2_(strm.ptr, windowBits, zlibVersion()?.toKString(), sizeOf<z_stream>().toInt()) != Z_OK) {
            return@memScoped null
        }
        try {
            val out = ArrayList<ByteArray>()
            var total = 0
            val chunk = ByteArray(64 * 1024)
            input.usePinned { inPinned ->
                strm.next_in = inPinned.addressOf(0).reinterpret<UByteVar>()
                strm.avail_in = input.size.convert()
                while (true) {
                    val produced =
                        chunk.usePinned { outPinned ->
                            strm.next_out = outPinned.addressOf(0).reinterpret<UByteVar>()
                            strm.avail_out = chunk.size.convert()
                            val rc = inflate(strm.ptr, Z_NO_FLUSH)
                            val n = chunk.size - strm.avail_out.toInt()
                            when (rc) {
                                Z_OK, Z_STREAM_END -> {}
                                // No progress possible: input ended before the stream did.
                                Z_BUF_ERROR -> return@usePinned null
                                else -> return@usePinned null
                            }
                            n to (rc == Z_STREAM_END)
                        } ?: return@memScoped null
                    val (n, done) = produced
                    if (n > 0) {
                        total += n
                        if (total > MAX_HTTP1_BODY) return@memScoped null
                        out += chunk.copyOf(n)
                    }
                    if (done) break
                    if (n == 0 && strm.avail_in == 0u) return@memScoped null
                }
            }
            val result = ByteArray(total)
            var at = 0
            for (part in out) {
                part.copyInto(result, at)
                at += part.size
            }
            result
        } finally {
            inflateEnd(strm.ptr)
        }
    }
