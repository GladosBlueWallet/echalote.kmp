package org.hazae41.echalote

internal actual fun inflateZlibOrNull(input: ByteArray): ByteArray? = InflateKt.inflateZlibOrNull(input)
