package io.bluewallet.echalote

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Trust anchor for the directory: the v3 identity fingerprints of the directory authorities.
 *
 * Copied from C tor src/app/config/auth_dirs.inc (the `v3ident=` values), tor main at
 * 6772a3b58657fbb1b9a19ea2db51ee8e9c1f777f; the file was last changed in
 * 39ba9ce0d7913ceb53fc1f1b4e2c2c129099fc4f ("dirauth: Add new faravahar", 2024-05-30).
 * These are the same nine authorities AUTHORITY_HOSTS points at. Serge is a bridge
 * authority and has no v3ident. Update this list together with AUTHORITY_HOSTS.
 */
internal object DirectoryAuthorities {
    val V3_IDENTITIES: Set<String> =
        setOf(
            "F533C81CEF0BC0267857C99B2F471ADF249FA232", // moria1
            "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", // tor26
            "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", // dizum
            "ED03BB616EB2F60BEC80151114BB25CEF515B226", // gabelmoo
            "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", // dannenberg
            "49015F787433103580E3B66A1707A00E60F2D15B", // maatuska
            "23D15D965BC35114467363C165C4F724B64B4F66", // longclaw
            "27102BC123E7AF1D4741AE047E160C91ADC76B21", // bastet
            "70849B868D606BAECFB6128C5E3D782029AA394F", // faravahar
        )

    /**
     * A consensus is accepted with valid signatures from at least this many distinct pinned
     * authorities. This is a deliberate project choice, looser than C tor (which requires more
     * than half of the configured authorities, i.e. 5 of 9) and matching the upstream JS client.
     */
    const val MIN_VALID_SIGNATURES = 3
}

internal class SignedBytes(
    val data: ByteArray,
    val signature: ByteArray,
)

/** A `dir-key-certificate-version 3` document (dir-spec "Creating key certificates"). */
internal class AuthorityKeyCert(
    val fingerprint: String,
    /** dir-key-published..dir-key-expires. */
    val validMillis: LongRange,
    /** PKCS#1 RSAPublicKey DER. */
    val identityKey: ByteArray,
    /** PKCS#1 RSAPublicKey DER. */
    val signingKey: ByteArray,
    val crossCert: ByteArray,
    /** Text from "dir-key-certificate-version" through the newline after "dir-key-certification", and its signature. */
    val certification: SignedBytes,
) {
    val publishedMillis: Long get() = validMillis.first
    val expiresMillis: Long get() = validMillis.last

    /** Upper-case hex SHA-1 of the signing key DER, as used in `directory-signature` lines. */
    val signingKeyDigest: String = bytesToHex(Sha1.hash(signingKey)).uppercase()
}

internal object AuthorityKeyCertParser {
    private const val START = "dir-key-certificate-version "
    private const val CERTIFICATION = "\ndir-key-certification\n"

    /** Parses every certificate in [text]. Malformed certificates are skipped, never repaired. */
    fun parseAll(text: String): List<AuthorityKeyCert> {
        val starts = ArrayList<Int>()
        var at = if (text.startsWith(START)) 0 else text.indexOf("\n$START").let { if (it < 0) -1 else it + 1 }
        while (at >= 0) {
            starts += at
            val next = text.indexOf("\n$START", at)
            at = if (next < 0) -1 else next + 1
        }
        val out = ArrayList<AuthorityKeyCert>()
        for ((n, start) in starts.withIndex()) {
            val end = starts.getOrNull(n + 1) ?: text.length
            parseOne(text.substring(start, end))?.let { out += it }
        }
        return out
    }

    private fun parseOne(block: String): AuthorityKeyCert? =
        try {
            parseOrThrow(block)
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: IndexOutOfBoundsException) {
            null
        }

    private fun parseOrThrow(block: String): AuthorityKeyCert {
        val cut = block.indexOf(CERTIFICATION)
        require(cut > 0) { "missing dir-key-certification" }
        val lines = block.split("\n")
        require(lines[0] == "${START}3") { "unsupported key certificate version" }
        val fields = CertFields()
        var i = 1
        while (i < lines.size) i = fields.take(lines, i) + 1
        return fields.build(block.substring(0, cut + CERTIFICATION.length).encodeToByteArray())
    }

    private class CertFields {
        private val seen = HashSet<String>()
        private val objects = HashMap<String, ByteArray>()
        private var fingerprint: String? = null
        private var published: Long? = null
        private var expires: Long? = null

        /** Consumes the item starting at lines[i]; returns the index of its last line. */
        fun take(
            lines: List<String>,
            i: Int,
        ): Int {
            val line = lines[i]
            val keyword = line.substringBefore(' ')
            if (keyword in SINGLE) require(seen.add(keyword)) { "duplicate $keyword" }
            val types = OBJECT_TYPES[keyword]
            return when {
                types != null -> {
                    val (bytes, last) = readObject(lines, i + 1, types)
                    objects[keyword] = bytes
                    if (keyword == "dir-key-certification") {
                        require(lines.drop(last + 1).all { it.isBlank() }) { "data after dir-key-certification" }
                    }
                    last
                }
                keyword == "fingerprint" -> i.also { fingerprint = line.removePrefix("fingerprint ").uppercase() }
                keyword == "dir-key-published" -> i.also { published = parseConsensusTime(line.removePrefix("dir-key-published ")) }
                keyword == "dir-key-expires" -> i.also { expires = parseConsensusTime(line.removePrefix("dir-key-expires ")) }
                else -> i
            }
        }

        fun build(certified: ByteArray): AuthorityKeyCert {
            val fp = requireNotNull(fingerprint) { "missing fingerprint" }
            require(fp.length == 40 && fp.all { it in HEX }) { "bad fingerprint" }
            val from = requireNotNull(published) { "missing dir-key-published" }
            val until = requireNotNull(expires) { "missing dir-key-expires" }

            fun obj(keyword: String) = requireNotNull(objects[keyword]) { "missing $keyword" }
            return AuthorityKeyCert(
                fingerprint = fp,
                validMillis = from..until,
                identityKey = obj("dir-identity-key"),
                signingKey = obj("dir-signing-key"),
                crossCert = obj("dir-key-crosscert"),
                certification = SignedBytes(certified, obj("dir-key-certification")),
            )
        }
    }

    private val OBJECT_TYPES =
        mapOf(
            "dir-identity-key" to setOf("RSA PUBLIC KEY"),
            "dir-signing-key" to setOf("RSA PUBLIC KEY"),
            "dir-key-crosscert" to setOf("ID SIGNATURE", "SIGNATURE"),
            "dir-key-certification" to setOf("SIGNATURE"),
        )

    private val SINGLE =
        setOf(
            "fingerprint",
            "dir-key-published",
            "dir-key-expires",
            "dir-identity-key",
            "dir-signing-key",
            "dir-key-crosscert",
            "dir-key-certification",
        )

    private fun readObject(
        lines: List<String>,
        start: Int,
        types: Set<String>,
    ): Pair<ByteArray, Int> {
        val type =
            lines[start].removePrefix("-----BEGIN ").removeSuffix("-----").takeIf {
                lines[start].startsWith("-----BEGIN ") && lines[start].endsWith("-----")
            }
        require(type != null && type in types) { "unexpected object ${lines[start]}" }
        val body = StringBuilder()
        var i = start + 1
        while (lines[i] != "-----END $type-----") {
            require(!lines[i].startsWith("-----")) { "bad object" }
            body.append(lines[i])
            i++
        }
        return Base64.decode(body.toString()) to i
    }
}

private const val HEX = "0123456789ABCDEF"

/**
 * Checks one authority key certificate. Returns null if it can be used, else why not.
 *
 * Trust comes only from [pinned]: the identity key must hash to a pinned fingerprint, the
 * certificate must be signed by that identity key, the signing key must cross-certify the
 * identity, and [now] must be inside dir-key-published..dir-key-expires.
 */
internal fun checkAuthorityKeyCert(
    cert: AuthorityKeyCert,
    pinned: Set<String>,
    now: Long,
): String? {
    val timing = CertCheckTiming()
    val identityDigest = timing.measure(CertCheckTiming.Part.FINGERPRINT) { Sha1.hash(cert.identityKey) }
    val verdict =
        when {
            cert.fingerprint !in pinned -> "unpinned identity"
            bytesToHex(identityDigest).uppercase() != cert.fingerprint -> "fingerprint mismatch"
            now < cert.publishedMillis -> "not yet published"
            now > cert.expiresMillis -> "expired"
            else -> checkAuthorityKeyCertSignatures(cert, identityDigest, timing)
        }
    timing.log(cert.fingerprint, verdict)
    return verdict
}

/** Per-certificate timing; one log line per certificate. */
private class CertCheckTiming {
    enum class Part(
        val key: String,
    ) {
        FINGERPRINT("fpSha1"),
        KEY_PARSE("keyParse"),
        CERT_SHA1("certSha1"),
        CERT_MODPOW("certModPow"),
        CERT_RSA("certRsaTotal"),
        CROSS_MODPOW("crossModPow"),
        CROSS_RSA("crossRsaTotal"),
    }

    private val start = timeMark()
    private val parts = LinkedHashMap<Part, kotlin.time.Duration>()

    inline fun <T> measure(
        part: Part,
        block: () -> T,
    ): T {
        val mark = timeMark()
        try {
            return block()
        } finally {
            add(part, mark.elapsedNow())
        }
    }

    /** Times an RSA verify ([total], including [block]'s other work) and its modPow part. */
    inline fun rsa(
        total: Part,
        modPow: Part,
        key: RsaPublicKey,
        block: () -> Boolean,
    ): Boolean {
        val ok = measure(total, block)
        add(modPow, key.lastModPow)
        return ok
    }

    fun add(
        part: Part,
        d: kotlin.time.Duration,
    ) {
        parts[part] = (parts[part] ?: kotlin.time.Duration.ZERO) + d
    }

    fun log(
        fingerprint: String,
        verdict: String?,
    ) {
        val detail = parts.entries.joinToString(" ") { "${it.key.key}=${it.value.msText()}" }
        logTiming("consensus", "cert-check", start.elapsedNow(), "fp=${fingerprint.take(8)} ok=${verdict == null} $detail")
    }
}

private fun rsaKeyOrNull(pkcs1: ByteArray): RsaPublicKey? =
    try {
        RsaPublicKey.fromPkcs1Der(Memory(pkcs1))
    } catch (_: IllegalArgumentException) {
        null
    } catch (_: IndexOutOfBoundsException) {
        null
    }

/** Tor signs the raw SHA-1 digest with PKCS#1 v1.5 padding and no DigestInfo. */
private fun checkAuthorityKeyCertSignatures(
    cert: AuthorityKeyCert,
    identityDigest: ByteArray,
    timing: CertCheckTiming,
): String? {
    val identity = timing.measure(CertCheckTiming.Part.KEY_PARSE) { rsaKeyOrNull(cert.identityKey) }
    val signing = timing.measure(CertCheckTiming.Part.KEY_PARSE) { rsaKeyOrNull(cert.signingKey) }
    return when {
        identity == null || signing == null -> "bad key"
        !timing.rsa(CertCheckTiming.Part.CERT_RSA, CertCheckTiming.Part.CERT_MODPOW, identity) {
            val certified = timing.measure(CertCheckTiming.Part.CERT_SHA1) { Sha1.hash(cert.certification.data) }
            identity.verifyPkcs1v15Unprefixed(Memory(certified), Memory(cert.certification.signature))
        } -> "bad certification signature"
        !timing.rsa(CertCheckTiming.Part.CROSS_RSA, CertCheckTiming.Part.CROSS_MODPOW, signing) {
            signing.verifyPkcs1v15Unprefixed(Memory(identityDigest), Memory(cert.crossCert))
        } -> "bad cross-certificate"
        else -> null
    }
}

internal fun acceptAuthorityKeyCerts(
    certs: List<AuthorityKeyCert>,
    pinned: Set<String>,
    now: Long,
    checkpoint: () -> Unit = {},
): List<AuthorityKeyCert> =
    certs.filter {
        checkpoint()
        checkAuthorityKeyCert(it, pinned, now) == null
    }

/**
 * Verifies the `directory-signature`s of [consensus] (dir-spec "Footer", C tor
 * networkstatus_check_consensus_signature). Returns the distinct pinned authorities with a
 * valid signature, or throws if that is fewer than
 * [DirectoryAuthorities.MIN_VALID_SIGNATURES]. [checkpoint] runs before each signature check
 * and may throw to stop the work.
 */
internal fun verifyConsensusSignaturesOrThrow(
    consensus: Consensus,
    certs: Collection<AuthorityKeyCert>,
    pinned: Set<String>,
    now: Long,
    checkpoint: () -> Unit = {},
): Set<String> {
    val preimage = requireNotNull(consensus.preimage) { "consensus has no signatures" }
    require(preimage.startsWith("network-status-version ") && preimage.endsWith("\ndirectory-signature ")) {
        "bad consensus signature boundary"
    }
    val digests = ConsensusDigests(timed("consensus", "preimage-encode", { "chars=${preimage.length}" }) { preimage.encodeToByteArray() })
    val usable =
        timed("consensus", "certs-recheck", { "certs=${certs.size}" }) {
            acceptAuthorityKeyCerts(certs.toList(), pinned, now, checkpoint)
        }.associateBy { it.fingerprint to it.signingKeyDigest }
    val good = HashSet<String>()
    for (sig in consensus.signatures) {
        checkpoint()
        if (sig.identity.uppercase() in pinned && isValidConsensusSignature(sig, usable, digests)) good += sig.identity.uppercase()
    }
    val required = DirectoryAuthorities.MIN_VALID_SIGNATURES
    check(good.size >= required) { "consensus has ${good.size} valid authority signatures, need $required" }
    return good
}

private class ConsensusDigests(
    private val signed: ByteArray,
) {
    val sha256 by lazy { timed("consensus", "preimage-digest", { "alg=sha256 bytes=${signed.size}" }) { Sha256.hash(signed) } }
    val sha1 by lazy { timed("consensus", "preimage-digest", { "alg=sha1 bytes=${signed.size}" }) { Sha1.hash(signed) } }

    fun forAlgorithm(algorithm: String): ByteArray? =
        when (algorithm) {
            "sha256" -> sha256
            "sha1" -> sha1
            else -> null
        }
}

private fun isValidConsensusSignature(
    sig: ConsensusSignature,
    usable: Map<Pair<String, String>, AuthorityKeyCert>,
    digests: ConsensusDigests,
): Boolean {
    val start = timeMark()
    var modPow = kotlin.time.Duration.ZERO
    val digest = digests.forAlgorithm(sig.algorithm)
    val afterDigest = start.elapsedNow()
    val cert = usable[sig.identity.uppercase() to sig.signingKeyDigest.uppercase()]
    val key = cert?.let { rsaKeyOrNull(it.signingKey) }
    val ok =
        digest != null &&
            key != null &&
            try {
                key.verifyPkcs1v15Unprefixed(Memory(digest), Memory(Base64.decode(sig.signature))).also { modPow = key.lastModPow }
            } catch (_: IllegalArgumentException) {
                false
            }
    logTiming(
        "consensus",
        "signature",
        start.elapsedNow(),
        "id=${sig.identity.take(8)} alg=${sig.algorithm} ok=$ok digest=${afterDigest.msText()} modPow=${modPow.msText()}",
    )
    return ok
}

/** Verified authority key certificates, kept until they expire. */
internal class AuthorityCertStore {
    private val mutex = Mutex()
    private val certs = LinkedHashMap<Pair<String, String>, AuthorityKeyCert>()

    /**
     * Returns usable certificates for the pinned signers of [consensus], fetching missing ones
     * with [fetch] (given a `/tor/keys/fp-sk/...` path). Only certificates that pass
     * [checkAuthorityKeyCert] are kept.
     */
    suspend fun certsFor(
        consensus: Consensus,
        pinned: Set<String>,
        now: Long,
        checkpoint: () -> Unit = {},
        fetch: suspend (path: String) -> String,
    ): List<AuthorityKeyCert> {
        val waitStart = timeMark()
        return mutex.withLock {
            logTiming("consensus", "cert-store-wait", waitStart.elapsedNow())
            certs.values.removeAll { now > it.expiresMillis }
            val wanted =
                consensus.signatures
                    .map { it.identity.uppercase() to it.signingKeyDigest.uppercase() }
                    .filter { (id, sk) -> id in pinned && sk.length == 40 && sk.all { it in HEX } }
                    .distinct()
            val missing = wanted.filter { it !in certs }
            println("echalote.consensus certs wanted=${wanted.size} cached=${wanted.size - missing.size} fetch=${missing.size}")
            if (missing.isNotEmpty()) {
                val text =
                    timed("consensus", "key-fetch", { "certs=${missing.size}" }) {
                        fetch("/tor/keys/fp-sk/" + missing.joinToString("+") { "${it.first}-${it.second}" })
                    }
                val parsed = timed("consensus", "key-parse", { "chars=${text.length}" }) { AuthorityKeyCertParser.parseAll(text) }
                for (cert in acceptAuthorityKeyCerts(parsed, pinned, now, checkpoint)) {
                    certs[cert.fingerprint to cert.signingKeyDigest] = cert
                }
            }
            wanted.mapNotNull { certs[it] }
        }
    }
}

internal val defaultAuthorityCertStore = AuthorityCertStore()
