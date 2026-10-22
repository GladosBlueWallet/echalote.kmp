package io.bluewallet.echalote

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.TimeSource

internal const val TLS_ECDHE_RSA_AES256_GCM_SHA384 = 0xC030
internal const val TLS_HANDSHAKE_TIMEOUT_MS = 20_000L
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
private const val ALERT_FATAL = 2
private const val ALERT_HANDSHAKE_FAILURE = 40
private const val ALERT_BAD_CERTIFICATE = 42
private const val ALERT_ILLEGAL_PARAMETER = 47
private const val ALERT_DECODE_ERROR = 50
private const val ALERT_DECRYPT_ERROR = 51
private const val MAX_HANDSHAKE_MESSAGE = 128 * 1024

internal open class TlsAlertError(
    message: String,
) : Exception(message)

internal class TlsCloseNotify : TlsAlertError("TLS close_notify")

internal fun tlsPumpError(error: Throwable): Throwable? = if (error is TlsCloseNotify) null else error

private fun throwTlsAlert(body: ByteArray): Nothing {
    val level = if (body.isNotEmpty()) body.u8(0) else -1
    val desc = if (body.size >= 2) body.u8(1) else -1
    if (desc == 0) throw TlsCloseNotify()
    throw TlsAlertError("TLS alert level=$level desc=$desc")
}

/**
 * Userspace TLS 1.2 client: ECDHE_RSA_WITH_AES_256_GCM_SHA384.
 * With [TlsTrust.WebPki] (default) the server chain is verified by the platform and the
 * host name against the leaf's subjectAltName, both before ClientKeyExchange; [TlsTrust.TorLink] skips PKI and only exposes the
 * leaf certificate DER for Tor CERTS `sign_to_tls`.
 */
internal class TlsClientDuplex(
    private val hostName: String? = null,
    recordTransport: ByteDuplex? = null,
    internal val trust: TlsTrust = TlsTrust.WebPki,
) {
    val inner: ByteDuplex
    val outer: ByteDuplex
    val leafCertDer = CompletableDeferred<ByteArray>()
    val ready = CompletableDeferred<Unit>()
    var pumpError: Throwable? = null
        internal set
    private val job = SupervisorJob()
    internal val scope = CoroutineScope(job + Dispatchers.Default)

    init {
        val (innerPub, innerPriv) = pairedByteDuplexes()
        val (outerPub, outerPriv) = pairedByteDuplexes()
        inner = innerPub
        outer = outerPub
        val transport = recordTransport ?: innerPriv
        scope.launch {
            try {
                handshakeAndPump(transport, outerPriv, hostName)
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

private class TlsEngine(
    val transport: ByteDuplex,
) {
    var readSeq = 0L
    var writeSeq = 0L
    var readKey: ByteArray = ByteArray(0)
    var writeKey: ByteArray = ByteArray(0)
    var readIv: ByteArray = ByteArray(0)
    var writeIv: ByteArray = ByteArray(0)
    var encryptedRead = false
    var encryptedWrite = false
    val writeMutex = Mutex()

    suspend fun writeRecord(
        type: Int,
        fragment: ByteArray,
    ) = writeMutex.withLock {
        val body = if (encryptedWrite) seal(type, fragment) else fragment
        val hdr = ByteArray(5)
        hdr[0] = type.toByte()
        hdr.putU16be(1, TLS_VERSION)
        hdr.putU16be(3, body.size)
        transport.write(concatBytes(hdr, body))
    }

    /** Best effort: the handshake is being abandoned either way. */
    suspend fun sendFatalAlert(description: Int) {
        try {
            writeRecord(REC_ALERT, byteArrayOf(ALERT_FATAL.toByte(), description.toByte()))
        } catch (_: Throwable) {
        }
    }

    suspend fun readRecord(): Pair<Int, ByteArray> {
        val hdr = transport.readExact(5)
        val type = hdr.u8(0)
        val len = hdr.u16be(3)
        require(len in 1..18432) { "bad TLS record length $len" }
        val fragment = transport.readExact(len)
        if (type == REC_ALERT && !encryptedRead) {
            throwTlsAlert(fragment)
        }
        val body = if (encryptedRead) open(type, fragment) else fragment
        if (type == REC_ALERT) {
            throwTlsAlert(body)
        }
        return type to body
    }

    private fun seal(
        type: Int,
        plaintext: ByteArray,
    ): ByteArray {
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

    private fun open(
        type: Int,
        fragment: ByteArray,
    ): ByteArray {
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

private data class TlsSession(
    val leaf: ByteArray,
    val tls: TlsEngine,
)

private sealed class TlsNext {
    data class Handshake(
        val type: Int,
        val body: ByteArray,
        val raw: ByteArray,
    ) : TlsNext()

    data object Ccs : TlsNext()
}

private suspend fun runTlsHandshake(
    transport: ByteDuplex,
    hostName: String?,
    trust: TlsTrust,
): TlsSession {
    // Only WebPKI-verified sessions are ever cached, so only WebPKI may resume one.
    val cached =
        hostName
            ?.takeIf { it.isNotEmpty() && trust == TlsTrust.WebPki }
            ?.let { lookupTlsSession(it) }
    val tls = TlsEngine(transport)
    val hs = HandshakeBuf(tls)
    val clientRandom = secureRandom(32)
    val clientHello = buildClientHello(clientRandom, hostName, cached)
    hs.transcript = concatBytes(hs.transcript, clientHello)
    tls.writeRecord(REC_HS, clientHello)
    println("echalote.tls $hostName hello-sent")

    // A malformed or out-of-order server flight is answered with a fatal alert before giving up.
    return runCatching {
        val (helloType, helloBody, helloRaw) = hs.next()
        require(helloType == HS_SERVER_HELLO) { "expected ServerHello" }
        hs.transcript = concatBytes(hs.transcript, helloRaw)
        val hello = parseServerHello(helloBody)
        val next = hs.nextOrCcs()
        val flow = TlsHandshake(tls, hs, hostName, clientRandom, trust)
        val resume = cached
        val abbreviated =
            next is TlsNext.Ccs ||
                (next is TlsNext.Handshake && next.type == HS_NEW_SESSION_TICKET)
        if (resume != null && abbreviated) {
            println("echalote.tls $hostName resume=true")
            flow.finishResume(resume, hello, next)
        } else {
            println("echalote.tls $hostName resume=false")
            flow.finishFull(hello, next)
        }
    }.getOrElse { e ->
        val alert =
            when (e) {
                is CancellationException -> null // an IllegalStateException, but not the peer's fault
                is IllegalArgumentException, is IndexOutOfBoundsException -> ALERT_DECODE_ERROR
                is IllegalStateException -> ALERT_HANDSHAKE_FAILURE
                else -> null
            }
        alert?.let { tls.sendFatalAlert(it) }
        throw e
    }
}

private class FullServerAuth {
    var chain: List<ByteArray> = emptyList()
    val leaf: ByteArray get() = chain.firstOrNull() ?: ByteArray(0)
    var peerPoint: ByteArray = ByteArray(0)
    var ecdheParams: ByteArray = ByteArray(0)
    var sigHash: Int = 0
    var signature: ByteArray = ByteArray(0)
    var ticket: ByteArray = ByteArray(0)
    var lifetime: Long = 0L
}

private class TlsHandshake(
    val tls: TlsEngine,
    val hs: HandshakeBuf,
    val hostName: String?,
    val clientRandom: ByteArray,
    val trust: TlsTrust,
) {
    fun installKeys(
        master: ByteArray,
        serverRandom: ByteArray,
    ) {
        val keyBlock = tlsPrfSha384(master, "key expansion", concatBytes(serverRandom, clientRandom), 72)
        tls.writeKey = keyBlock.copyOfRange(0, 32)
        tls.readKey = keyBlock.copyOfRange(32, 64)
        tls.writeIv = keyBlock.copyOfRange(64, 68)
        tls.readIv = keyBlock.copyOfRange(68, 72)
    }

    fun keepSession(
        master: ByteArray,
        sessionId: ByteArray,
        ticket: ByteArray,
        ems: Boolean,
        expiresAtMs: Long,
    ) {
        val host = hostName ?: return
        // Only WebPKI-verified sessions are cached; a TorLink session must never be resumed.
        val resumable = ticket.isNotEmpty() || sessionId.isNotEmpty()
        if (trust != TlsTrust.WebPki || host.isEmpty() || !resumable) return
        storeTlsResumption(
            TlsResumption(
                host = host,
                master = master,
                sessionId = sessionId,
                ticket = ticket,
                ems = ems,
                expiresAtMs = expiresAtMs,
            ),
        )
        println("echalote.tls $host ticket=${ticket.size} sid=${sessionId.size}")
    }

    suspend fun finishResume(
        cached: TlsResumption,
        hello: ParsedServerHello,
        first: TlsNext,
    ): TlsSession {
        if (cached.ems != hello.ems) {
            hostName?.let { forgetTlsSession(it) }
            error("TLS resume EMS mismatch")
        }
        installKeys(cached.master, hello.serverRandom)
        var ticket = cached.ticket
        var lifetime = 0L
        when (first) {
            is TlsNext.Handshake -> {
                require(first.type == HS_NEW_SESSION_TICKET) { "expected NewSessionTicket on resume" }
                hs.transcript = concatBytes(hs.transcript, first.raw)
                val parsed = parseNewSessionTicket(first.body)
                ticket = parsed.ticket
                lifetime = parsed.lifetimeHintSec
                val (rtype, frag) = tls.readRecord()
                require(rtype == REC_CCS && frag.contentEquals(byteArrayOf(1))) { "expected CCS after ticket" }
                tls.encryptedRead = true
                tls.readSeq = 0
            }
            is TlsNext.Ccs -> {
                tls.encryptedRead = true
                tls.readSeq = 0
            }
        }
        val (rtype, frag) = tls.readRecord()
        require(rtype == REC_HS) { "expected server Finished" }
        val (ht, hb, raw) = parseHandshake(frag)
        require(ht == HS_FINISHED) { "expected Finished, got $ht" }
        val expect = tlsPrfSha384(cached.master, "server finished", Sha384.hash(hs.transcript), 12)
        if (!equalBytes(hb, expect)) {
            hostName?.let { forgetTlsSession(it) }
            error("TLS server Finished mismatch")
        }
        hs.transcript = concatBytes(hs.transcript, raw)
        tls.writeRecord(REC_CCS, byteArrayOf(1))
        tls.encryptedWrite = true
        tls.writeSeq = 0
        val clientFinished = tlsPrfSha384(cached.master, "client finished", Sha384.hash(hs.transcript), 12)
        tls.writeRecord(REC_HS, handshakeMessage(HS_FINISHED, clientFinished))
        val sid = if (hello.sessionId.isNotEmpty()) hello.sessionId else cached.sessionId
        // Resumption re-verifies nothing, so it must not extend the original session's life.
        keepSession(cached.master, sid, ticket, cached.ems, tlsResumeExpiryMs(lifetime, ceilingMs = cached.expiresAtMs))
        return TlsSession(ByteArray(0), tls)
    }

    suspend fun finishFull(
        hello: ParsedServerHello,
        first: TlsNext,
    ): TlsSession {
        val auth = readFullServerAuth(first)
        verifyServerKeyExchange(auth, hello)
        if (trust == TlsTrust.WebPki) {
            val started = TimeSource.Monotonic.markNow()
            try {
                verifyWebPkiChain(auth.chain, hostName)
            } catch (e: TlsCertificateError) {
                rejectServerAuth(ALERT_BAD_CERTIFICATE, e)
            }
            val ms = started.elapsedNow().inWholeMilliseconds
            println("echalote.tls $hostName certificate verified chain=${auth.chain.size} ms=$ms")
        }
        val master = sendClientKeyExchange(auth, hello)
        readServerFinished(auth, master)
        val expiresAtMs = tlsResumeExpiryMs(auth.lifetime, ceilingMs = chainResumeCeilingMs(auth.chain))
        keepSession(master, hello.sessionId, auth.ticket, hello.ems, expiresAtMs)
        return TlsSession(auth.leaf, tls)
    }

    /** Server authentication failed before any key was sent: alert the peer, then throw. */
    private suspend fun rejectServerAuth(
        alert: Int,
        error: TlsCertificateError,
    ): Nothing {
        tls.sendFatalAlert(alert)
        println("echalote.tls $hostName certificate rejected: ${error.message}")
        throw error
    }

    private suspend fun readFullServerAuth(first: TlsNext): FullServerAuth {
        require(first is TlsNext.Handshake) { "expected Certificate after ServerHello" }
        val auth = FullServerAuth()
        var type = first.type
        var body = first.body
        var raw = first.raw
        var gotHelloDone = false
        while (true) {
            hs.transcript = concatBytes(hs.transcript, raw)
            when (type) {
                HS_CERTIFICATE -> {
                    require(auth.chain.isEmpty()) { "duplicate Certificate" }
                    auth.chain =
                        try {
                            parseCertificateChain(body)
                        } catch (e: IllegalArgumentException) {
                            rejectServerAuth(ALERT_DECODE_ERROR, TlsCertificateError("TLS: malformed Certificate message: ${e.message}", e))
                        }
                }
                HS_SERVER_KEY_EXCHANGE -> {
                    require(auth.peerPoint.isEmpty()) { "duplicate ServerKeyExchange" }
                    takeServerKeyExchange(auth, body)
                }
                HS_SERVER_HELLO_DONE -> gotHelloDone = true
                HS_NEW_SESSION_TICKET -> {
                    val parsed = parseNewSessionTicket(body)
                    auth.ticket = parsed.ticket
                    auth.lifetime = parsed.lifetimeHintSec
                }
                HS_CERTIFICATE_STATUS -> {}
                else -> error("unexpected handshake type $type")
            }
            if (gotHelloDone) break
            val n = hs.next()
            type = n.first
            body = n.second
            raw = n.third
        }
        require(auth.leaf.isNotEmpty() && auth.peerPoint.isNotEmpty()) { "incomplete TLS handshake" }
        return auth
    }

    private fun takeServerKeyExchange(
        auth: FullServerAuth,
        body: ByteArray,
    ) {
        require(body.size >= 4) { "short ServerKeyExchange" }
        require(body[0].toInt() == 3) { "expected named_curve" }
        require(body.u16be(1) == 0x0017) { "expected secp256r1" }
        val plen = body.u8(3)
        require(plen > 0 && 4 + plen + 4 <= body.size) { "truncated ServerKeyExchange" }
        auth.peerPoint = body.copyOfRange(4, 4 + plen)
        auth.ecdheParams = body.copyOfRange(0, 4 + plen)
        var o = 4 + plen
        auth.sigHash = body.u8(o)
        o += 1
        val sigId = body.u8(o)
        o += 1
        require(sigId == 1) { "expected RSA signature" }
        val slen = body.u16be(o)
        o += 2
        require(o + slen == body.size) { "ServerKeyExchange signature length mismatch" }
        auth.signature = body.copyOfRange(o, o + slen)
    }

    private suspend fun verifyServerKeyExchange(
        auth: FullServerAuth,
        hello: ParsedServerHello,
    ) {
        val x509 =
            runCatching { X509Certificate.parse(auth.leaf) }.getOrElse { e ->
                rejectServerAuth(ALERT_BAD_CERTIFICATE, TlsCertificateError("TLS: unparseable server certificate: ${e.message}", e))
            }
        val signed = concatBytes(clientRandom, hello.serverRandom, auth.ecdheParams)
        val (hash, prefix) =
            try {
                serverKeyExchangeDigest(auth.sigHash, signed)
            } catch (e: IllegalArgumentException) {
                rejectServerAuth(ALERT_ILLEGAL_PARAMETER, TlsCertificateError("TLS: ${e.message}", e))
            }
        val ok =
            runCatching { x509.rsaPublicKey().verifyPkcs1v15Digest(prefix, hash, auth.signature) }.getOrElse { e ->
                rejectServerAuth(ALERT_BAD_CERTIFICATE, TlsCertificateError("TLS: unusable server public key: ${e.message}", e))
            }
        if (!ok) rejectServerAuth(ALERT_DECRYPT_ERROR, TlsCertificateError("TLS ServerKeyExchange signature failed"))
    }

    private suspend fun sendClientKeyExchange(
        auth: FullServerAuth,
        hello: ParsedServerHello,
    ): ByteArray {
        val (secret, public) = P256.generateKeyPair()
        val premaster = P256.ecdh(secret, auth.peerPoint)
        val cke = handshakeMessage(HS_CLIENT_KEY_EXCHANGE, concatBytes(byteArrayOf(public.size.toByte()), public))
        hs.transcript = concatBytes(hs.transcript, cke)
        tls.writeRecord(REC_HS, cke)
        val sessionHash = Sha384.hash(hs.transcript)
        val master =
            if (hello.ems) {
                tlsPrfSha384(premaster, "extended master secret", sessionHash, 48)
            } else {
                tlsPrfSha384(premaster, "master secret", concatBytes(clientRandom, hello.serverRandom), 48)
            }
        installKeys(master, hello.serverRandom)
        tls.writeRecord(REC_CCS, byteArrayOf(1))
        tls.encryptedWrite = true
        tls.writeSeq = 0
        val clientFinished = tlsPrfSha384(master, "client finished", Sha384.hash(hs.transcript), 12)
        val fin = handshakeMessage(HS_FINISHED, clientFinished)
        hs.transcript = concatBytes(hs.transcript, fin)
        tls.writeRecord(REC_HS, fin)
        return master
    }

    private suspend fun readServerFinished(
        auth: FullServerAuth,
        master: ByteArray,
    ) {
        var gotCcs = false
        var serverOk = false
        while (!serverOk) {
            val (rtype, frag) = tls.readRecord()
            if (rtype == REC_CCS) {
                require(frag.contentEquals(byteArrayOf(1)))
                tls.encryptedRead = true
                tls.readSeq = 0
                gotCcs = true
            } else if (rtype == REC_HS && !gotCcs) {
                val (ht, hb, hraw) = parseHandshake(frag)
                hs.transcript = concatBytes(hs.transcript, hraw)
                if (ht == HS_NEW_SESSION_TICKET) {
                    val parsed = parseNewSessionTicket(hb)
                    auth.ticket = parsed.ticket
                    auth.lifetime = parsed.lifetimeHintSec
                }
            } else {
                require(gotCcs && rtype == REC_HS) { "expected encrypted Finished" }
                val (ht, hb, fraw) = parseHandshake(frag)
                require(ht == HS_FINISHED) { "expected Finished, got $ht" }
                val expect = tlsPrfSha384(master, "server finished", Sha384.hash(hs.transcript), 12)
                require(equalBytes(hb, expect)) { "TLS server Finished mismatch" }
                hs.transcript = concatBytes(hs.transcript, fraw)
                serverOk = true
            }
        }
    }
}

private suspend fun TlsClientDuplex.handshakeAndPump(
    transport: ByteDuplex,
    app: ByteDuplex,
    hostName: String?,
) {
    val session = runTlsHandshake(transport, hostName, trust)
    leafCertDer.complete(session.leaf)
    val tls = session.tls

    suspend fun pumpIncoming() {
        runCatching {
            while (true) {
                val (type, frag) = tls.readRecord()
                if (type == REC_CCS) continue
                if (type != REC_APP) {
                    if (type == REC_HS) continue
                    throw TlsAlertError("unexpected TLS record $type")
                }
                if (frag.isNotEmpty()) app.write(frag)
            }
        }.onFailure { e ->
            pumpError = tlsPumpError(e)
            try {
                app.close()
            } catch (_: Throwable) {
            }
        }
    }
    ready.complete(Unit)
    var incoming: kotlinx.coroutines.Job? = null
    try {
        while (true) {
            val chunk = app.read(16 * 1024)
            if (chunk.isEmpty()) break
            tls.writeRecord(REC_APP, chunk)
            if (incoming == null) incoming = scope.launch { pumpIncoming() }
        }
    } catch (_: Throwable) {
    } finally {
        incoming?.cancel()
        try {
            transport.close()
        } catch (_: Throwable) {
        }
    }
}

private class HandshakeBuf(
    val tls: TlsEngine,
) {
    var buf = ByteArray(0)
    var transcript = ByteArray(0)

    suspend fun next(): Triple<Int, ByteArray, ByteArray> {
        while (buf.size < 4) pull()
        val len = (buf.u8(1) shl 16) or buf.u16be(2)
        require(len <= MAX_HANDSHAKE_MESSAGE) { "TLS handshake message too large: $len" }
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

    suspend fun nextOrCcs(): TlsNext {
        while (!hasCompleteHandshake()) {
            val (type, frag) = tls.readRecord()
            if (type == REC_CCS) return TlsNext.Ccs
            require(type == REC_HS) { "expected handshake or CCS, got $type" }
            buf = concatBytes(buf, frag)
        }
        val (ht, body, raw) = takeHandshake()
        return TlsNext.Handshake(ht, body, raw)
    }

    private fun hasCompleteHandshake(): Boolean {
        if (buf.size < 4) return false
        val len = (buf.u8(1) shl 16) or buf.u16be(2)
        require(len <= MAX_HANDSHAKE_MESSAGE) { "TLS handshake message too large: $len" }
        return buf.size >= 4 + len
    }

    private fun takeHandshake(): Triple<Int, ByteArray, ByteArray> {
        val len = (buf.u8(1) shl 16) or buf.u16be(2)
        val raw = buf.copyOfRange(0, 4 + len)
        buf = buf.copyOfRange(4 + len, buf.size)
        val (t, b, _) = parseHandshake(raw)
        return Triple(t, b, raw)
    }
}

private fun parseHandshake(raw: ByteArray): Triple<Int, ByteArray, ByteArray> {
    require(raw.size >= 4)
    val type = raw.u8(0)
    val len = (raw.u8(1) shl 16) or raw.u16be(2)
    require(raw.size >= 4 + len)
    return Triple(type, raw.copyOfRange(4, 4 + len), raw.copyOfRange(0, 4 + len))
}

private fun handshakeMessage(
    type: Int,
    body: ByteArray,
): ByteArray {
    val out = ByteArray(4 + body.size)
    out[0] = type.toByte()
    out[1] = (body.size ushr 16).toByte()
    out.putU16be(2, body.size)
    body.copyInto(out, 4)
    return out
}

private fun buildClientHello(
    random: ByteArray,
    hostName: String?,
    resume: TlsResumption? = null,
): ByteArray {
    val sni =
        // RFC 6066 §3: IP literals are not permitted in server_name.
        if (hostName.isNullOrEmpty() || parseIpLiteral(hostName.removeSuffix(".")) != null) {
            ByteArray(0)
        } else {
            val host = hostName.encodeToByteArray()
            val nameEntry = concatBytes(byteArrayOf(0), u16(host.size), host)
            tlsExt(0x0000, concatBytes(u16(nameEntry.size), nameEntry))
        }
    val ticket = resume?.ticket ?: ByteArray(0)
    val sid =
        if (resume != null && ticket.isEmpty()) resume.sessionId else ByteArray(0)
    val exts =
        concatBytes(
            sni,
            tlsExt(
                0x000d,
                run {
                    val algs = byteArrayOf(0x04, 0x01, 0x05, 0x01)
                    concatBytes(u16(algs.size), algs)
                },
            ),
            tlsExt(0x000a, concatBytes(u16(2), byteArrayOf(0x00, 0x17))),
            tlsExt(0x000b, byteArrayOf(1, 0)),
            tlsExt(0x0017, ByteArray(0)),
            tlsExt(0xff01, byteArrayOf(0)),
            tlsExt(TLS_SESSION_TICKET_EXT, ticket),
        )
    val body =
        concatBytes(
            u16(TLS_VERSION),
            random,
            byteArrayOf(sid.size.toByte()),
            sid,
            u16(2),
            u16(TLS_ECDHE_RSA_AES256_GCM_SHA384),
            byteArrayOf(1, 0),
            u16(exts.size),
            exts,
        )
    return handshakeMessage(HS_CLIENT_HELLO, body)
}

private fun tlsExt(
    type: Int,
    data: ByteArray,
): ByteArray = concatBytes(u16(type), u16(data.size), data)

private fun u16(v: Int): ByteArray {
    val b = ByteArray(2)
    b.putU16be(0, v)
    return b
}

/** Library-internal [wrapTls] that may select [TlsTrust.TorLink] (tests and the Tor OR link only). */
internal suspend fun wrapTlsWithTrust(
    transport: ByteDuplex,
    hostName: String,
    abort: Abort?,
    trust: TlsTrust,
): ByteDuplex {
    val tls = TlsClientDuplex(hostName, transport, trust)
    try {
        withAbortTimeout(TLS_HANDSHAKE_TIMEOUT_MS, abort) { _ -> tls.ready.await() }
    } catch (err: Throwable) {
        hostName.takeIf { it.isNotEmpty() }?.let { forgetTlsSession(it) }
        tls.close()
        throw err
    }
    return object : ByteDuplex {
        override suspend fun read(n: Int): ByteArray {
            val value = tls.outer.read(n)
            if (value.isEmpty()) {
                val err = tls.pumpError
                if (err != null) throw err
            }
            return value
        }

        override suspend fun write(bytes: ByteArray) {
            val err = tls.pumpError
            if (err != null) throw err
            tls.outer.write(bytes)
        }

        override fun close() {
            try {
                tls.close()
            } catch (_: Throwable) {
            }
            try {
                transport.close()
            } catch (_: Throwable) {
            }
        }
    }
}
