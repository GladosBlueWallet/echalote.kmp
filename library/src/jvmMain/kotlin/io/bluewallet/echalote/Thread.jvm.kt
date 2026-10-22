package io.bluewallet.echalote

internal actual fun currentThreadName(): String = Thread.currentThread().name.replace(' ', '_')
