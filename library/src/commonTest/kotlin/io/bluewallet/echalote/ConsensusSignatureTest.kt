package io.bluewallet.echalote

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Inside the fixture consensus validity window (02:00..05:00 UTC). */
internal val FIXTURE_NOW = utcEpochMillis(2026, 10, 22, 3, 30, 0)

internal val fixtureConsensusText: String by lazy {
    val z = readTestFixture("consensus/consensus-microdesc-2026-10-22-0200.z")
    (inflateZlibOrNull(z) ?: error("bad fixture")).decodeToString()
}

internal val fixtureKeysText: String by lazy {
    readTestFixture("consensus/authority-keys-all-2026-10-22.txt").decodeToString()
}

internal val fixtureConsensus: Consensus by lazy { ConsensusParser.parseOrThrow(fixtureConsensusText) }

internal val fixtureCerts: List<AuthorityKeyCert> by lazy { AuthorityKeyCertParser.parseAll(fixtureKeysText) }

private const val MORIA1 = "F533C81CEF0BC0267857C99B2F471ADF249FA232"
private const val DANNENBERG = "0232AF901C31A04EE9848595AF9BB7620D4C5B2E"
private const val MAATUSKA = "49015F787433103580E3B66A1707A00E60F2D15B"
private const val BASTET = "27102BC123E7AF1D4741AE047E160C91ADC76B21"
private const val RETIRED = "EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97"
private const val SYNTHETIC = "C8313F0A407F1D7EE95F93D2F9D7D1D7EDD78583"
private val SYNTHETIC_NOW = utcEpochMillis(2026, 6, 1, 0, 0, 0)

class ConsensusSignatureTest {
    private val pinned = DirectoryAuthorities.V3_IDENTITIES

    private fun certText(fingerprint: String): String {
        val blocks = fixtureKeysText.split("dir-key-certificate-version ").drop(1)
        return "dir-key-certificate-version " + blocks.single { it.contains("\nfingerprint $fingerprint\n") }
    }

    private fun cert(fingerprint: String) = AuthorityKeyCertParser.parseAll(certText(fingerprint)).single()

    private fun synthetic(name: String) = AuthorityKeyCertParser.parseAll(readTestFixture("consensus/synthetic-$name.txt").decodeToString()).single()

    /** Keeps the signature blocks for [keep] (in that order, repeats allowed) and drops the rest. */
    private fun withSignatures(keep: List<String>): String {
        val text = fixtureConsensusText
        val head = text.substring(0, text.indexOf("\ndirectory-signature ") + 1)
        val blocks =
            text
                .substring(head.length)
                .split("directory-signature ")
                .filter { it.isNotEmpty() }
                .map { "directory-signature $it" }
        val out = StringBuilder(head)
        for (id in keep) out.append(blocks.first { it.split(" ")[2] == id })
        return out.toString()
    }

    private val signers: List<String> by lazy { fixtureConsensus.signatures.map { it.identity } }

    @Test
    fun pinsTheNineCurrentV3Authorities() {
        assertEquals(9, pinned.size)
        assertTrue(MORIA1 in pinned && BASTET in pinned)
        assertEquals(3, DirectoryAuthorities.MIN_VALID_SIGNATURES)
    }

    @Test
    fun preimageRunsThroughTheSpaceAfterTheFirstDirectorySignature() {
        val text = fixtureConsensusText
        val end = text.indexOf("\ndirectory-signature ") + "\ndirectory-signature ".length
        assertEquals(text.substring(0, end), fixtureConsensus.preimage)
        assertTrue(fixtureConsensus.preimage!!.startsWith("network-status-version 3 microdesc\n"))
    }

    @Test
    fun directorySignatureBeforeFooterIsRejected() {
        val text = fixtureConsensusText
        val sneaky = text.replaceFirst("\ndirectory-footer\n", "\ndirectory-signature sha256 AA BB\ndirectory-footer\n")
        assertFails { ConsensusParser.parseOrThrow(sneaky) }
    }

    @Test
    fun parsesSignatureAlgorithmAndDefaultsToSha1WhenOmitted() {
        val first = fixtureConsensus.signatures.first()
        assertEquals("sha256", first.algorithm)
        assertEquals(DANNENBERG, first.identity)
        assertEquals("79ABAEE942F8F0F6E5FEB989D2539B05AB86DD8B", first.signingKeyDigest)
        val legacy =
            fixtureConsensusText.replaceFirst(
                "directory-signature sha256 $DANNENBERG",
                "directory-signature $DANNENBERG",
            )
        val sig = ConsensusParser.parseOrThrow(legacy).signatures.first()
        assertEquals("sha1", sig.algorithm)
        assertEquals(DANNENBERG, sig.identity)
        assertEquals("79ABAEE942F8F0F6E5FEB989D2539B05AB86DD8B", sig.signingKeyDigest)
    }

    @Test
    fun genuineConsensusVerifiesWithEightAuthoritySignatures() {
        val good = verifyConsensusSignaturesOrThrow(fixtureConsensus, fixtureCerts, pinned, FIXTURE_NOW).size
        assertEquals(8, good)
        assertEquals(pinned - BASTET, verifyConsensusSignaturesOrThrow(fixtureConsensus, fixtureCerts, pinned, FIXTURE_NOW))
    }

    @Test
    fun tamperedRelayLineFails() {
        val text = fixtureConsensusText
        val start = text.indexOf("\nr ") + 1
        val line = text.substring(start, text.indexOf('\n', start))
        val parts = line.split(" ").toMutableList()
        parts[6] = if (parts[6] == "9001") "9002" else "9001"
        val tampered = text.replaceRange(start, start + line.length, parts.joinToString(" "))
        val parsed = ConsensusParser.parseOrThrow(tampered)
        val err = assertFails { verifyConsensusSignaturesOrThrow(parsed, fixtureCerts, pinned, FIXTURE_NOW) }
        assertTrue(err.message!!.contains("0 valid"), err.message)
    }

    @Test
    fun twoSignaturesFailAndThreePass() {
        val two = ConsensusParser.parseOrThrow(withSignatures(signers.take(2)))
        val err = assertFails { verifyConsensusSignaturesOrThrow(two, fixtureCerts, pinned, FIXTURE_NOW) }
        assertTrue(err.message!!.contains("2 valid"), err.message)
        assertTrue(err.message!!.contains("need 3"), err.message)
        val three = ConsensusParser.parseOrThrow(withSignatures(signers.take(3)))
        assertEquals(3, verifyConsensusSignaturesOrThrow(three, fixtureCerts, pinned, FIXTURE_NOW).size)
    }

    @Test
    fun repeatedSignaturesFromOneAuthorityCountOnce() {
        val keep = signers.take(2) + listOf(signers[0], signers[0], signers[1])
        val parsed = ConsensusParser.parseOrThrow(withSignatures(keep))
        assertEquals(5, parsed.signatures.size)
        val err = assertFails { verifyConsensusSignaturesOrThrow(parsed, fixtureCerts, pinned, FIXTURE_NOW) }
        assertTrue(err.message!!.contains("2 valid"), err.message)
    }

    @Test
    fun threeSignaturesFromUnpinnedOrUncertifiedAuthoritiesAreNotEnough() {
        val three = ConsensusParser.parseOrThrow(withSignatures(signers.take(3)))
        val err = assertFails { verifyConsensusSignaturesOrThrow(three, fixtureCerts, pinned - signers[0], FIXTURE_NOW) }
        assertTrue(err.message!!.contains("2 valid"), err.message)
        val certs = fixtureCerts.filter { it.fingerprint != signers[2] }
        assertFails { verifyConsensusSignaturesOrThrow(three, certs, pinned, FIXTURE_NOW) }
    }

    @Test
    fun signatureFromUnpinnedIdentityIsNotCounted() {
        val withoutMoria = pinned - MORIA1
        assertEquals(7, verifyConsensusSignaturesOrThrow(fixtureConsensus, fixtureCerts, withoutMoria, FIXTURE_NOW).size)
    }

    @Test
    fun signatureWithoutMatchingCertIsNotCounted() {
        val certs = fixtureCerts.filter { it.fingerprint != MORIA1 }
        assertEquals(7, verifyConsensusSignaturesOrThrow(fixtureConsensus, certs, pinned, FIXTURE_NOW).size)
    }

    @Test
    fun genuinePinnedCertsPassAndUnpinnedOrExpiredOnesAreRejected() {
        for (fp in signers) assertNull(checkAuthorityKeyCert(cert(fp), pinned, FIXTURE_NOW), fp)
        assertEquals("unpinned identity", checkAuthorityKeyCert(cert(RETIRED), pinned, FIXTURE_NOW))
        val accepted = acceptAuthorityKeyCerts(fixtureCerts, pinned, FIXTURE_NOW).map { it.fingerprint }.toSet()
        assertEquals(pinned, accepted)
    }

    @Test
    fun certCheckedAgainstClock() {
        val afterMaatuskaExpiry = utcEpochMillis(2026, 12, 9, 0, 0, 0)
        assertEquals("expired", checkAuthorityKeyCert(cert(MAATUSKA), pinned, afterMaatuskaExpiry))
        val beforeBastetPublished = utcEpochMillis(2026, 7, 1, 0, 0, 0)
        assertEquals("not yet published", checkAuthorityKeyCert(cert(BASTET), pinned, beforeBastetPublished))
        val good = verifyConsensusSignaturesOrThrow(fixtureConsensus, fixtureCerts, pinned, afterMaatuskaExpiry).size
        assertEquals(7, good)
    }

    @Test
    fun certWithSwappedSigningKeyFailsCertification() {
        val moria = certText(MORIA1)
        val other = certText(DANNENBERG)

        fun signingKey(t: String) = t.substring(t.indexOf("dir-signing-key\n"), t.indexOf("dir-key-crosscert\n"))
        val forged = AuthorityKeyCertParser.parseAll(moria.replace(signingKey(moria), signingKey(other))).single()
        assertEquals("bad certification signature", checkAuthorityKeyCert(forged, pinned, FIXTURE_NOW))
    }

    @Test
    fun certClaimingAnotherIdentityFailsFingerprintCheck() {
        val forged =
            AuthorityKeyCertParser
                .parseAll(certText(MORIA1).replace("fingerprint $MORIA1", "fingerprint $DANNENBERG"))
                .single()
        assertEquals("fingerprint mismatch", checkAuthorityKeyCert(forged, pinned, FIXTURE_NOW))
    }

    @Test
    fun syntheticAuthorityCertsIsolateEachCheck() {
        val only = setOf(SYNTHETIC)
        assertNull(checkAuthorityKeyCert(synthetic("good"), only, SYNTHETIC_NOW))
        assertEquals("unpinned identity", checkAuthorityKeyCert(synthetic("good"), pinned, SYNTHETIC_NOW))
        assertEquals(
            "bad certification signature",
            checkAuthorityKeyCert(synthetic("forged-certification"), only, SYNTHETIC_NOW),
        )
        assertEquals("bad cross-certificate", checkAuthorityKeyCert(synthetic("bad-crosscert"), only, SYNTHETIC_NOW))
    }
}
