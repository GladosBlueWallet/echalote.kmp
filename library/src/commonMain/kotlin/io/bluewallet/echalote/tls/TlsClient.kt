package io.bluewallet.echalote

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal const val TLS_ECDHE_RSA_AES256_GCM_SHA384 = 0xC030
private const val TLS_VERSION = 0x0303
private const val REC_CCS = 20
private const val REC_ALERT = 21
private const val REC_HS = 22
private const val REC_APP = 23
private const val HS_CLIENT_HELLO = 1
private const val HS_SERVER_HELLO = 2
private const val HS_NEW_SESSION_TICKET = 4
private const val HS_CERTIFICATE = 11
private const val HS_SERVER_KEY_EXCHANGE = 12
private const val HS_CERTIFICATE_STATUS = 22
private const val HS_SERVER_HELLO_DONE = 14
private const val HS_CLIENT_KEY_EXCHANGE = 16
private const val HS_FINISHED = 20

/**
 * Userspace TLS 1.2 client: ECDHE_RSA_WITH_AES_256_GCM_SHA384, no PKI trust.
 * Exposes the leaf certificate DER for Tor CERTS `sign_to_tls`.
 */
internal class TlsClientDuplex {
    val inner: ByteDuplex
    val outer: ByteDuplex
    val leafCertDer = CompletableDeferred<ByteArray>()
    val ready = CompletableDeferred<Unit>()
    private val job = SupervisorJob()
    internal val scope = CoroutineScope(job + Dispatchers.Default)

    init {
        val (innerPub, innerPriv) = pairedByteDuplexes()
        val (outerPub, outerPriv) = pairedByteDuplexes()
        inner = innerPub
        outer = outerPub
        scope.launch {
            try {
                handshakeAndPump(innerPriv, outerPriv)
            } catch (e: Throwable) {
                leafCertDer.completeExceptionally(e)
                ready.completeExceptionally(e)
                try {
                    innerPriv.close()
                } catch (_: Throwable) {
                }
                try {
                    outerPriv.close()
                } catch (_: Throwable) {
                }
            }
        }
    }

    fun close() {
        job.cancel()
        try {
            inner.close()
        } catch (_: Throwable) {
        }
        try {
            outer.close()
        } catch (_: Throwable) {
        }
    }
}

private class TlsEngine(val transport: ByteDuplex) {
    var readSeq = 0L
    var writeSeq = 0L
    var readKey: ByteArray = ByteArray(0)
    var writeKey: ByteArray = ByteArray(0)
    var readIv: ByteArray = ByteArray(0)
    var writeIv: ByteArray = ByteArray(0)
    var encryptedRead = false
    var encryptedWrite = false
    val writeMutex = Mutex()

    suspend fun writeRecord(type: Int, fragment: ByteArray) = writeMutex.withLock {
        val body = if (encryptedWrite) seal(type, fragment) else fragment
        val hdr = ByteArray(5)
        hdr[0] = type.toByte()
        hdr.putU16be(1, TLS_VERSION)
        hdr.putU16be(3, body.size)
        transport.write(concatBytes(hdr, body))
    }

    suspend fun readRecord(): Pair<Int, ByteArray> {
        val hdr = transport.readExact(5)
        val type = hdr.u8(0)
        val len = hdr.u16be(3)
        require(len in 1..18432) { "bad TLS record length $len" }
        val fragment = transport.readExact(len)
        if (type == REC_ALERT) {
            val desc = if (fragment.size >= 2) fragment.u8(1) else -1
            throw Exception("TLS alert $desc")
        }
        return if (encryptedRead) type to open(type, fragment) else type to fragment
    }

    private fun seal(type: Int, plaintext: ByteArray): ByteArray {
        val explicit = ByteArray(8)
        explicit.putU64be(0, writeSeq)
        val nonce = concatBytes(writeIv, explicit)
        val aad = ByteArray(13)
        aad.putU64be(0, writeSeq)
        aad[8] = type.toByte()
        aad.putU16be(9, TLS_VERSION)
        aad.putU16be(11, plaintext.size)
        val (ct, tag) = AesGcm.encrypt(writeKey, nonce, aad, plaintext)
        writeSeq += 1
        return concatBytes(explicit, ct, tag)
    }

    private fun open(type: Int, fragment: ByteArray): ByteArray {
        require(fragment.size >= 8 + 16) { "short GCM record" }
        val explicit = fragment.copyOfRange(0, 8)
        val tag = fragment.copyOfRange(fragment.size - 16, fragment.size)
        val ct = fragment.copyOfRange(8, fragment.size - 16)
        val nonce = concatBytes(readIv, explicit)
        val aad = ByteArray(13)
        aad.putU64be(0, readSeq)
        aad[8] = type.toByte()
        aad.putU16be(9, TLS_VERSION)
        aad.putU16be(11, ct.size)
        val pt = AesGcm.decrypt(readKey, nonce, aad, ct, tag)
        readSeq += 1
        return pt
    }
}

private data class TlsSession(val leaf: ByteArray, val tls: TlsEngine)

private suspend fun runTlsHandshake(transport: ByteDuplex): TlsSession {
    val tls = TlsEngine(transport)
    val hs = HandshakeBuf(tls)
    val clientRandom = secureRandom(32)
    val clientHello = buildClientHello(clientRandom)
    hs.transcript = concatBytes(hs.transcript, clientHello)
    tls.writeRecord(REC_HS, clientHello)

    var serverRandom = ByteArray(0)
    var leaf = ByteArray(0)
    var peerPoint = ByteArray(0)
    var ecdheParams = ByteArray(0)
    var sigHash = 0
    var signature = ByteArray(0)
    var ems = false
    var gotHelloDone = false
    while (!gotHelloDone) {
        val (type, body, raw) = hs.next()
        hs.transcript = concatBytes(hs.transcript, raw)
        when (type) {
            HS_SERVER_HELLO -> {
                require(body.size >= 34) { "short ServerHello" }
                serverRandom = body.copyOfRange(2, 34)
                var o = 34
                val sidLen = body.u8(o); o += 1 + sidLen
                val suite = body.u16be(o); o += 2
                require(suite == TLS_ECDHE_RSA_AES256_GCM_SHA384) { "unexpected cipher $suite" }
                o += 1
                if (o + 2 <= body.size) {
                    val extLen = body.u16be(o); o += 2
                    val end = o + extLen
                    while (o + 4 <= end) {
                        val et = body.u16be(o)
                        val el = body.u16be(o + 2)
                        o += 4
                        if (et == 0x0017) ems = true
                        o += el
                    }
                }
            }
            HS_CERTIFICATE -> {
                require(body.size >= 3) { "short Certificate" }
                var o = 3
                val certLen = (body.u8(o) shl 16) or body.u16be(o + 1)
                o += 3
                leaf = body.copyOfRange(o, o + certLen)
            }
            HS_SERVER_KEY_EXCHANGE -> {
                require(body[0].toInt() == 3) { "expected named_curve" }
                require(body.u16be(1) == 0x0017) { "expected secp256r1" }
                val plen = body.u8(3)
                peerPoint = body.copyOfRange(4, 4 + plen)
                ecdheParams = body.copyOfRange(0, 4 + plen)
                var o = 4 + plen
                sigHash = body.u8(o); o += 1
                val sigId = body.u8(o); o += 1
                require(sigId == 1) { "expected RSA signature" }
                val slen = body.u16be(o); o += 2
                signature = body.copyOfRange(o, o + slen)
            }
            HS_SERVER_HELLO_DONE -> gotHelloDone = true
            HS_NEW_SESSION_TICKET, HS_CERTIFICATE_STATUS -> {}
            else -> throw Exception("unexpected handshake type $type")
        }
    }
    require(leaf.isNotEmpty() && peerPoint.isNotEmpty()) { "incomplete TLS handshake" }
    val x509 = X509Certificate.parse(leaf)
    val signed = concatBytes(clientRandom, serverRandom, ecdheParams)
    val (hash, prefix) = when (sigHash) {
        4 -> Sha256.hash(signed) to RsaPublicKey.SHA256_DIGESTINFO
        5 -> Sha384.hash(signed) to RsaPublicKey.SHA384_DIGESTINFO
        2 -> Sha1.hash(signed) to RsaPublicKey.SHA1_DIGESTINFO
        else -> throw Exception("unsupported TLS signature hash $sigHash")
    }
    require(x509.rsaPublicKey().verifyPkcs1v15Digest(prefix, hash, signature)) {
        "TLS ServerKeyExchange signature failed"
    }

    val (secret, public) = P256.generateKeyPair()
    val premaster = P256.ecdh(secret, peerPoint)
    val cke = handshakeMessage(HS_CLIENT_KEY_EXCHANGE, concatBytes(byteArrayOf(public.size.toByte()), public))
    hs.transcript = concatBytes(hs.transcript, cke)
    tls.writeRecord(REC_HS, cke)

    val sessionHash = Sha384.hash(hs.transcript)
    val master = if (ems) {
        tlsPrfSha384(premaster, "extended master secret", sessionHash, 48)
    } else {
        tlsPrfSha384(premaster, "master secret", concatBytes(clientRandom, serverRandom), 48)
    }
    val keyBlock = tlsPrfSha384(master, "key expansion", concatBytes(serverRandom, clientRandom), 72)
    tls.writeKey = keyBlock.copyOfRange(0, 32)
    tls.readKey = keyBlock.copyOfRange(32, 64)
    tls.writeIv = keyBlock.copyOfRange(64, 68)
    tls.readIv = keyBlock.copyOfRange(68, 72)

    tls.writeRecord(REC_CCS, byteArrayOf(1))
    tls.encryptedWrite = true
    tls.writeSeq = 0

    val clientFinished = tlsPrfSha384(master, "client finished", Sha384.hash(hs.transcript), 12)
    val fin = handshakeMessage(HS_FINISHED, clientFinished)
    hs.transcript = concatBytes(hs.transcript, fin)
    tls.writeRecord(REC_HS, fin)

    var gotCcs = false
    var serverOk = false
    while (!serverOk) {
        val (rtype, frag) = tls.readRecord()
        if (rtype == REC_CCS) {
            require(frag.contentEquals(byteArrayOf(1)))
            tls.encryptedRead = true
            tls.readSeq = 0
            gotCcs = true
            continue
        }
        if (rtype == REC_HS && !gotCcs) {
            val (_, _, raw) = parseHandshake(frag)
            hs.transcript = concatBytes(hs.transcript, raw)
            continue
        }
        require(gotCcs && rtype == REC_HS) { "expected encrypted Finished" }
        val (ht, hb, raw) = parseHandshake(frag)
        require(ht == HS_FINISHED) { "expected Finished, got $ht" }
        val expect = tlsPrfSha384(master, "server finished", Sha384.hash(hs.transcript), 12)
        require(equalBytes(hb, expect)) { "TLS server Finished mismatch" }
        hs.transcript = concatBytes(hs.transcript, raw)
        serverOk = true
    }
    return TlsSession(leaf, tls)
}

private suspend fun TlsClientDuplex.handshakeAndPump(transport: ByteDuplex, app: ByteDuplex) {
    val session = runTlsHandshake(transport)
    leafCertDer.complete(session.leaf)
    ready.complete(Unit)
    val tls = session.tls
    val incoming = scope.launch {
        try {
            while (true) {
                val (type, frag) = tls.readRecord()
                if (type == REC_CCS) continue
                if (type != REC_APP) {
                    if (type == REC_HS) continue
                    throw Exception("unexpected TLS record $type")
                }
                if (frag.isNotEmpty()) app.write(frag)
            }
        } catch (_: Throwable) {
            try {
                app.close()
            } catch (_: Throwable) {
            }
        }
    }
    try {
        while (true) {
            val chunk = app.read(16 * 1024)
            if (chunk.isEmpty()) break
            tls.writeRecord(REC_APP, chunk)
        }
    } catch (_: Throwable) {
    } finally {
        incoming.cancel()
        try {
            transport.close()
        } catch (_: Throwable) {
        }
    }
}

private class HandshakeBuf(val tls: TlsEngine) {
    var buf = ByteArray(0)
    var transcript = ByteArray(0)

    suspend fun next(): Triple<Int, ByteArray, ByteArray> {
        while (buf.size < 4) pull()
        val len = (buf.u8(1) shl 16) or buf.u16be(2)
        while (buf.size < 4 + len) pull()
        val raw = buf.copyOfRange(0, 4 + len)
        buf = buf.copyOfRange(4 + len, buf.size)
        val (t, b, _) = parseHandshake(raw)
        return Triple(t, b, raw)
    }

    private suspend fun pull() {
        val (type, frag) = tls.readRecord()
        require(type == REC_HS) { "expected handshake record, got $type" }
        buf = concatBytes(buf, frag)
    }
}

private fun parseHandshake(raw: ByteArray): Triple<Int, ByteArray, ByteArray> {
    require(raw.size >= 4)
    val type = raw.u8(0)
    val len = (raw.u8(1) shl 16) or raw.u16be(2)
    require(raw.size >= 4 + len)
    return Triple(type, raw.copyOfRange(4, 4 + len), raw.copyOfRange(0, 4 + len))
}

private fun handshakeMessage(type: Int, body: ByteArray): ByteArray {
    val out = ByteArray(4 + body.size)
    out[0] = type.toByte()
    out[1] = (body.size ushr 16).toByte()
    out.putU16be(2, body.size)
    body.copyInto(out, 4)
    return out
}

private fun buildClientHello(random: ByteArray): ByteArray {
    val exts = concatBytes(
        tlsExt(0x000d, run {
            val algs = byteArrayOf(0x04, 0x01, 0x05, 0x01)
            concatBytes(u16(algs.size), algs)
        }),
        tlsExt(0x000a, concatBytes(u16(2), byteArrayOf(0x00, 0x17))),
        tlsExt(0x000b, byteArrayOf(1, 0)),
        tlsExt(0x0017, ByteArray(0)),
        tlsExt(0xff01, byteArrayOf(0)),
    )
    val body = concatBytes(
        u16(TLS_VERSION),
        random,
        byteArrayOf(0),
        u16(2),
        u16(TLS_ECDHE_RSA_AES256_GCM_SHA384),
        byteArrayOf(1, 0),
        u16(exts.size),
        exts,
    )
    return handshakeMessage(HS_CLIENT_HELLO, body)
}

private fun tlsExt(type: Int, data: ByteArray): ByteArray =
    concatBytes(u16(type), u16(data.size), data)

private fun u16(v: Int): ByteArray {
    val b = ByteArray(2)
    b.putU16be(0, v)
    return b
}
