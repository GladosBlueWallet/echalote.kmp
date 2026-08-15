package org.hazae41.echalote

internal class X509Certificate(
    val der: ByteArray,
    val tbsDer: ByteArray,
    val spkiDer: ByteArray,
    val signature: ByteArray,
    val signatureOid: ByteArray,
    val notBeforeMillis: Long,
    val notAfterMillis: Long,
) {
    fun rsaPublicKey(): RsaPublicKey = RsaPublicKey.fromPublicKeyDer(Memory(spkiDer))

    fun verifySelfSigned(): Boolean {
        val hash = when {
            equalBytes(signatureOid, OID_SHA256_RSA) -> Sha256.hash(tbsDer)
            equalBytes(signatureOid, OID_SHA384_RSA) -> Sha384.hash(tbsDer)
            equalBytes(signatureOid, OID_SHA1_RSA) -> Sha1.hash(tbsDer)
            else -> return false
        }
        val prefix = when {
            equalBytes(signatureOid, OID_SHA256_RSA) -> RsaPublicKey.SHA256_DIGESTINFO
            equalBytes(signatureOid, OID_SHA384_RSA) -> RsaPublicKey.SHA384_DIGESTINFO
            else -> RsaPublicKey.SHA1_DIGESTINFO
        }
        return rsaPublicKey().verifyPkcs1v15Digest(prefix, hash, signature)
    }

    fun checkValidity(now: Long = currentEpochMillis()) {
        if (now > notAfterMillis) throw ExpiredCertError()
        if (now < notBeforeMillis) throw PrematureCertError()
    }

    companion object {
        val OID_SHA256_RSA = hexToBytes("2a864886f70d01010b")
        val OID_SHA384_RSA = hexToBytes("2a864886f70d01010c")
        val OID_SHA1_RSA = hexToBytes("2a864886f70d010105")

        fun parse(der: ByteArray): X509Certificate {
            val cert = Der.parse(der)
            val seq = cert.asSequence()
            require(seq.size >= 3) { "truncated X.509" }
            val tbs = seq[0]
            val sigAlg = seq[1]
            val sigBits = seq[2]
            val tbsChildren = tbs.asSequence()
            var i = 0
            if (tbsChildren[0].tag == 0xa0) i++
            i++ // serial
            i++ // signature alg
            i++ // issuer
            val validity = tbsChildren[i++]
            val times = validity.asSequence()
            val notBefore = parseTime(times[0])
            val notAfter = parseTime(times[1])
            i++ // subject
            val spki = tbsChildren[i]
            val sigOid = sigAlg.asSequence()[0].asOid()
            return X509Certificate(
                der = der,
                tbsDer = tbs.raw,
                spkiDer = spki.raw,
                signature = sigBits.asBitStringBytes(),
                signatureOid = sigOid,
                notBeforeMillis = notBefore,
                notAfterMillis = notAfter,
            )
        }

        private fun parseTime(der: Der): Long {
            val s = der.body.decodeToString().trimEnd('Z')
            val year: Int
            val rest: String
            if (der.tag == 0x17) {
                val yy = s.substring(0, 2).toInt()
                year = if (yy < 50) 2000 + yy else 1900 + yy
                rest = s.substring(2)
            } else {
                year = s.substring(0, 4).toInt()
                rest = s.substring(4)
            }
            val month = rest.substring(0, 2).toInt()
            val day = rest.substring(2, 4).toInt()
            val hour = rest.substring(4, 6).toInt()
            val minute = rest.substring(6, 8).toInt()
            val second = if (rest.length >= 10) rest.substring(8, 10).toInt() else 0
            return utcEpochMillis(year, month, day, hour, minute, second)
        }
    }
}

internal fun utcEpochMillis(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int): Long {
    val md = intArrayOf(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    fun leap(y: Int) = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    var days = 0L
    for (y in 1970 until year) days += if (leap(y)) 366 else 365
    for (m in 1 until month) {
        days += md[m - 1]
        if (m == 2 && leap(year)) days += 1
    }
    days += (day - 1)
    return (((days * 24 + hour) * 60 + minute) * 60 + second) * 1000
}
