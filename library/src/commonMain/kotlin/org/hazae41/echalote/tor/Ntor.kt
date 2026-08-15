package org.hazae41.echalote

internal data class KDFTorResult(
    val keyHash: ByteArray,
    val forwardDigest: ByteArray,
    val backwardDigest: ByteArray,
    val forwardKey: ByteArray,
    val backwardKey: ByteArray,
) {
    companion object {
        fun computeOrThrow(k0: ByteArray): KDFTorResult {
            val ki = ByteArray(k0.size + 1)
            k0.copyInto(ki)
            val k = ByteArray(HASH_LEN * 5)
            var off = 0
            var i = 0
            while (off < k.size) {
                ki[ki.size - 1] = i.toByte()
                val h = Sha1.hash(ki)
                val n = minOf(HASH_LEN, k.size - off)
                h.copyInto(k, off, 0, n)
                off += n
                i++
            }
            val cur = Cursor(k)
            return KDFTorResult(
                keyHash = cur.read(HASH_LEN),
                forwardDigest = cur.read(HASH_LEN),
                backwardDigest = cur.read(HASH_LEN),
                forwardKey = cur.read(KEY_LEN),
                backwardKey = cur.read(KEY_LEN),
            )
        }
    }
}

internal data class NtorRequest(
    val publicX: ByteArray,
    val relayidRsa: ByteArray,
    val ntorOnionKey: ByteArray,
) {
    fun size() = relayidRsa.size + ntorOnionKey.size + publicX.size
    fun write(cursor: Cursor) {
        cursor.write(relayidRsa)
        cursor.write(ntorOnionKey)
        cursor.write(publicX)
    }
}

internal data class NtorResponse(val publicY: ByteArray, val auth: ByteArray) {
    companion object {
        fun read(cursor: Cursor) = NtorResponse(cursor.read(32), cursor.read(32))
    }
}

internal data class NtorResult(
    val auth: ByteArray,
    val nonce: ByteArray,
    val forwardDigest: ByteArray,
    val backwardDigest: ByteArray,
    val forwardKey: ByteArray,
    val backwardKey: ByteArray,
) {
    companion object {
        fun finalizeOrThrow(
            sharedXy: ByteArray,
            sharedXb: ByteArray,
            relayidRsa: ByteArray,
            publicB: ByteArray,
            publicX: ByteArray,
            publicY: ByteArray,
        ): NtorResult {
            val protoid = "ntor-curve25519-sha256-1"
            val secretInput = concatBytes(
                sharedXy, sharedXb, relayidRsa, publicB, publicX, publicY, utf8Bytes(protoid),
            )
            val tMac = utf8Bytes("$protoid:mac")
            val tKey = utf8Bytes("$protoid:key_extract")
            val tVerify = utf8Bytes("$protoid:verify")
            val verify = hmacSha256(tVerify, secretInput)
            val authInput = concatBytes(
                verify, relayidRsa, publicB, publicY, publicX, utf8Bytes(protoid), utf8Bytes("Server"),
            )
            val auth = hmacSha256(tMac, authInput)
            val mExpand = utf8Bytes("$protoid:key_expand")
            val keyBytes = hkdfSha256(secretInput, tKey, mExpand, HASH_LEN * 3 + KEY_LEN * 2)
            val key = Cursor(keyBytes)
            val forwardDigest = key.read(HASH_LEN)
            val backwardDigest = key.read(HASH_LEN)
            val forwardKey = key.read(KEY_LEN)
            val backwardKey = key.read(KEY_LEN)
            val nonce = key.read(HASH_LEN)
            return NtorResult(auth, nonce, forwardDigest, backwardDigest, forwardKey, backwardKey)
        }
    }
}
