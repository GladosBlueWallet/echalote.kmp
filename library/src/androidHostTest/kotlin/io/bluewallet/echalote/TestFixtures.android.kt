package io.bluewallet.echalote

import java.io.File

internal actual fun readTestFixture(path: String): ByteArray = File(TEST_FIXTURE_DIR, path).readBytes()

internal actual fun testEnv(name: String): String? = System.getenv(name)
