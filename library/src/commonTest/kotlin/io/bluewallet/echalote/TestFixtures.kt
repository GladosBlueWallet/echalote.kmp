package io.bluewallet.echalote

import kotlin.time.Duration.Companion.minutes

/** Reads a file under src/commonTest/resources. */
internal expect fun readTestFixture(path: String): ByteArray

/**
 * Wall-clock timeout for runTest bodies that verify consensus signatures. runTest's default is
 * 60 s, and the pure-Kotlin RSA checks already take about 40 s per test on a linuxX64 debug test
 * binary and more on the 3-core macOS CI runner's iOS simulator, where they hit that limit.
 */
internal val RSA_TEST_TIMEOUT = 5.minutes
