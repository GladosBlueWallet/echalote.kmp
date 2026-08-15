package org.hazae41.echalote

import java.security.SecureRandom

private val rng = SecureRandom()

internal actual fun fillSecureRandom(bytes: ByteArray) {
    rng.nextBytes(bytes)
}

internal actual fun currentEpochMillis(): Long = System.currentTimeMillis()
