package io.bluewallet.echalote

internal actual fun inflateZlibOrNull(input: ByteArray): ByteArray? = InflateKt.inflateZlibOrNull(input)

internal actual fun inflateGzipOrNull(input: ByteArray): ByteArray? = InflateKt.inflateGzipOrNull(input)
