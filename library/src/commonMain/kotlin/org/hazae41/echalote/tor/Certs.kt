package org.hazae41.echalote

internal class RsaCert(
    val type: Int,
    val data: ByteArray,
    val x509: X509Certificate,
) {
    fun sha1OrThrow(): ByteArray = Sha1.hash(x509.spkiDer)
    fun verifyOrThrow(): Boolean {
        x509.checkValidity()
        return true
    }
    companion object {
        const val RSA_TO_TLS = 1
        const val RSA_SELF = 2
        const val RSA_TO_AUTH = 3
        fun read(cursor: Cursor): RsaCert {
            val type = cursor.readU8()
            val length = cursor.readU16()
            val data = cursor.read(length)
            return RsaCert(type, data, X509Certificate.parse(data))
        }
    }
}

internal class CrossCert(
    val type: Int,
    val key: ByteArray,
    val expirationMillis: Long,
    val payload: ByteArray,
    val signature: ByteArray,
) {
    fun verifyOrThrow(): Boolean {
        if (currentEpochMillis() > expirationMillis) throw ExpiredCertError()
        return true
    }
    companion object {
        const val RSA_TO_ED = 7
        fun read(cursor: Cursor): CrossCert {
            val type = cursor.readU8()
            cursor.readU16()
            val start = cursor.offset
            val key = cursor.read(32)
            val hours = cursor.readU32()
            val expiration = hours.toLong() * 60 * 60 * 1000
            val content = cursor.offset - start
            cursor.offset = start
            val payload = cursor.read(content)
            val sigLen = cursor.readU8()
            val signature = cursor.read(sigLen)
            return CrossCert(type, key, expiration, payload, signature)
        }
    }
}

internal class Ed25519Cert(
    val type: Int,
    val certKey: ByteArray,
    val expirationMillis: Long,
    val payload: ByteArray,
    val signature: ByteArray,
    val signer: ByteArray?,
) {
    fun verifyOrThrow(): Boolean {
        if (currentEpochMillis() > expirationMillis) throw ExpiredCertError()
        val key = signer ?: return true
        if (!Ed25519.verify(key, payload, signature)) throw InvalidSignatureError()
        return true
    }
    companion object {
        const val ED_TO_SIGN = 4
        const val SIGN_TO_TLS = 5
        const val SIGN_TO_AUTH = 6
        const val SIGNER_EXT = 4
        const val AFFECTS_VALIDATION = 1
        fun read(cursor: Cursor): Ed25519Cert {
            val type = cursor.readU8()
            cursor.readU16()
            val start = cursor.offset
            cursor.readU8()
            cursor.readU8()
            val hours = cursor.readU32()
            val expiration = hours.toLong() * 60 * 60 * 1000
            cursor.readU8()
            val certKey = cursor.read(32)
            val nExt = cursor.readU8()
            var signer: ByteArray? = null
            repeat(nExt) {
                val length = cursor.readU16()
                val et = cursor.readU8()
                val flags = cursor.readU8()
                if (et == SIGNER_EXT) {
                    signer = cursor.read(32)
                } else {
                    if (flags == AFFECTS_VALIDATION) throw UnknownCertExtensionError(et)
                    cursor.read(length)
                }
            }
            val content = cursor.offset - start
            cursor.offset = start
            val payload = cursor.read(content)
            val signature = cursor.read(64)
            return Ed25519Cert(type, certKey, expiration, payload, signature, signer)
        }
    }
}

internal class TorCerts(
    val rsaSelf: RsaCert,
    val rsaToEd: CrossCert,
    val edToSign: Ed25519Cert,
    val signToTls: Ed25519Cert,
)

internal fun parseCertsCell(payload: ByteArray): PartialCerts {
    val c = Cursor(payload)
    val count = c.readU8()
    val out = PartialCerts()
    repeat(count) {
        val offset = c.offset
        val type = c.readU8()
        val length = c.readU16()
        c.offset = offset
        val bytes = c.read(1 + 2 + length)
        val cc = Cursor(bytes)
        when (type) {
            RsaCert.RSA_SELF -> {
                if (out.rsaSelf != null) throw DuplicatedCertError()
                out.rsaSelf = RsaCert.read(cc)
            }
            RsaCert.RSA_TO_AUTH -> out.rsaToAuth = RsaCert.read(cc)
            RsaCert.RSA_TO_TLS -> out.rsaToTls = RsaCert.read(cc)
            CrossCert.RSA_TO_ED -> {
                if (out.rsaToEd != null) throw DuplicatedCertError()
                out.rsaToEd = CrossCert.read(cc)
            }
            Ed25519Cert.ED_TO_SIGN -> {
                if (out.edToSign != null) throw DuplicatedCertError()
                out.edToSign = Ed25519Cert.read(cc)
            }
            Ed25519Cert.SIGN_TO_TLS -> {
                if (out.signToTls != null) throw DuplicatedCertError()
                out.signToTls = Ed25519Cert.read(cc)
            }
            Ed25519Cert.SIGN_TO_AUTH -> out.signToAuth = Ed25519Cert.read(cc)
            else -> throw UnknownCertError()
        }
    }
    return out
}

internal class PartialCerts {
    var rsaSelf: RsaCert? = null
    var rsaToAuth: RsaCert? = null
    var rsaToTls: RsaCert? = null
    var rsaToEd: CrossCert? = null
    var edToSign: Ed25519Cert? = null
    var signToTls: Ed25519Cert? = null
    var signToAuth: Ed25519Cert? = null
}

internal fun verifyTorCerts(pcerts: PartialCerts, tlsLeafDer: ByteArray): TorCerts {
    val rsaSelf = pcerts.rsaSelf ?: throw ExpectedCertError()
    val rsaToEd = pcerts.rsaToEd ?: throw ExpectedCertError()
    val edToSign = pcerts.edToSign ?: throw ExpectedCertError()
    val signToTls = pcerts.signToTls ?: throw ExpectedCertError()
    if (rsaSelf.verifyOrThrow() != true) throw Exception("Could not verify ID_SELF cert")
    if (rsaSelf.x509.spkiDer.let { der ->
            val inner = Der.parse(der).asSequence()[1].asBitStringBytes()
            inner.size != 12 + 128
        }
    ) throw InvalidCertError()
    if (!rsaSelf.x509.verifySelfSigned()) throw InvalidSignatureError()
    if (rsaToEd.verifyOrThrow() != true) throw Exception("Could not verify ID_TO_ED cert")
    val prefix = utf8Bytes("Tor TLS RSA/Ed25519 cross-certificate")
    val hashed = Sha256.hash(concatBytes(prefix, rsaToEd.payload))
    val pub = RsaPublicKey.fromPublicKeyDer(Memory(rsaSelf.x509.spkiDer))
    if (!pub.verifyPkcs1v15Unprefixed(Memory(hashed), Memory(rsaToEd.signature))) {
        throw InvalidSignatureError()
    }
    if (edToSign.verifyOrThrow() != true) throw Exception("Could not verify ED_TO_SIGN cert")
    if (!Ed25519.verify(rsaToEd.key, edToSign.payload, edToSign.signature)) {
        throw InvalidSignatureError()
    }
    if (signToTls.verifyOrThrow() != true) throw Exception("Could not verify SIGNING_TO_TLS cert")
    if (!Ed25519.verify(edToSign.certKey, signToTls.payload, signToTls.signature)) {
        throw InvalidSignatureError()
    }
    val hash = Sha256.hash(tlsLeafDer)
    if (!equalBytes(hash, signToTls.certKey)) throw InvalidCertError()
    return TorCerts(rsaSelf, rsaToEd, edToSign, signToTls)
}
