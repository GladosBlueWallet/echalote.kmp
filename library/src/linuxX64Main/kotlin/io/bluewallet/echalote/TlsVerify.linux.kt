package io.bluewallet.echalote

/** linuxX64 has no platform trust store binding, so WebPKI verification always fails closed. */
internal actual suspend fun verifyServerChain(
    chainDer: List<ByteArray>,
    host: String,
): Unit = rejectCertificate("TLS certificate verification is not available on linuxX64 (no trust store)")
