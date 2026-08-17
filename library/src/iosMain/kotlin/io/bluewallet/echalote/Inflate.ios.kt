package io.bluewallet.echalote

internal actual fun inflateZlibOrNull(input: ByteArray): ByteArray? = InflateKt.inflateZlibOrNull(input)
