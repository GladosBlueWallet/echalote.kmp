package io.bluewallet.echalote

/** Reads a file under src/commonTest/resources. */
internal expect fun readTestFixture(path: String): ByteArray
