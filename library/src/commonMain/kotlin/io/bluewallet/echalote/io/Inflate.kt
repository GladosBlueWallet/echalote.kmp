package io.bluewallet.echalote

internal expect fun inflateZlibOrNull(input: ByteArray): ByteArray?

/** Decodes a gzip (RFC 1952) body, checking its CRC-32 and size; null when malformed. */
internal expect fun inflateGzipOrNull(input: ByteArray): ByteArray?
