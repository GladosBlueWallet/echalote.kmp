package io.bluewallet.echalote

import kotlinx.coroutines.CancellationException
import kotlin.concurrent.Volatile

/**
 * How a TLS connection authenticates the server certificate.
 *
 * Internal on purpose: the public API ([wrapTls], [Echalote.wrapTls], [httpsFetch]) always
 * uses [WebPki]. Only echalote's own Tor OR link may select [TorLink].
 */
internal enum class TlsTrust {
    /**
     * Normal HTTPS: the certificate chain must chain to a platform trust anchor
     * (JVM cacerts, Android Network Security Config, iOS trust store) and its
     * subjectAltName must match the requested host name. linuxX64 fails closed.
     */
    WebPki,

    /**
     * No PKI check at all. Only for the Tor OR link, whose authenticity comes from
     * the relay's signed CERTS cell (`sign_to_tls`). Never use for ordinary HTTPS.
     */
    TorLink,
}

/**
 * TLS 1.2 over [transport]; the result carries plaintext after the handshake.
 * The server certificate is always verified: it must chain to a platform trust anchor and
 * match [hostName], otherwise this throws [TlsCertificateError]. There is no public way to
 * turn verification off.
 */
suspend fun wrapTls(
    transport: ByteDuplex,
    hostName: String,
    abort: Abort? = null,
): ByteDuplex = wrapTlsWithTrust(transport, hostName, abort, TlsTrust.WebPki)

/** The server certificate chain or host name was rejected; the handshake was aborted. */
class TlsCertificateError(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

internal const val MAX_TLS_CHAIN_CERTS = 10

@Volatile
private var trustAnchorsOverride: List<ByteArray>? = null

/** DER certificates injected by JVM tests; when set they replace the JDK trust store. */
internal fun tlsTrustAnchorsOverride(): List<ByteArray>? = trustAnchorsOverride?.map { it.copyOf() }

/**
 * Test hook (JVM only): replace, or with null restore, the trust anchors used by [TlsTrust.WebPki].
 * Drops every cached TLS session so nothing verified under the old anchors is resumed.
 */
internal fun setTlsTrustAnchorsForTesting(anchorsDer: List<ByteArray>?) {
    trustAnchorsOverride = anchorsDer?.map { it.copyOf() }
    resetTlsSessionCache()
}

/**
 * Platform verification of a server chain (leaf first) for [host]: path building to a
 * trust anchor, validity dates and key usage. Throws on any failure. The host name is
 * always checked again by [verifyWebPkiChain], so it holds on every platform.
 */
internal expect suspend fun verifyServerChain(
    chainDer: List<ByteArray>,
    host: String,
)

/**
 * WebPKI check run by the TLS client before it sends ClientKeyExchange. Fails closed:
 * any problem (including platform errors) becomes [TlsCertificateError].
 */
internal suspend fun verifyWebPkiChain(
    chainDer: List<ByteArray>,
    host: String?,
) {
    // Only the single root dot is dropped: "example.com.." keeps an empty label and fails.
    val name = host?.removeSuffix(".")
    if (name.isNullOrEmpty()) rejectCertificate("TLS: no host name to verify the certificate against")
    if (chainDer.isEmpty()) rejectCertificate("TLS: server sent no certificate")
    when (val failure = runCatching { verifyServerChain(chainDer, name) }.exceptionOrNull()) {
        null -> Unit
        is CancellationException, is TlsCertificateError -> throw failure
        else -> rejectCertificate("TLS certificate for $name rejected: ${failure.message ?: failure::class.simpleName}", failure)
    }
    if (!certificateMatchesHost(chainDer[0], host ?: name)) rejectCertificate("TLS certificate does not match host $name")
}

internal fun rejectCertificate(
    message: String,
    cause: Throwable? = null,
): Nothing = throw TlsCertificateError(message, cause)
