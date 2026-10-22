package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

private const val SERVER_AUTH_TYPE = "ECDHE_RSA"

/**
 * Verifies the chain with the JDK's default PKIX trust manager (the runtime's cacerts, or the
 * javax.net.ssl.trustStore override): path to a trust anchor, validity, key usage and the
 * JDK's disabled-algorithm rules. The host name is checked in common code by [verifyWebPkiChain].
 */
internal actual suspend fun verifyServerChain(
    chainDer: List<ByteArray>,
    host: String,
) = withContext(Dispatchers.IO) {
    val factory = CertificateFactory.getInstance("X.509")
    val chain = chainDer.map { factory.generateCertificate(it.inputStream()) as X509Certificate }.toTypedArray()
    val tm = tlsTrustAnchorsOverride()?.let { trustManager(it) } ?: defaultTrustManager
    tm.checkServerTrusted(chain, SERVER_AUTH_TYPE)
}

private val defaultTrustManager: X509TrustManager by lazy { trustManager(null) }

/** [anchors] (tests only) replace the JDK trust store; null means the JDK default. */
private fun trustManager(anchors: List<ByteArray>?): X509TrustManager {
    val store =
        anchors?.let { list ->
            val factory = CertificateFactory.getInstance("X.509")
            KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                list.forEachIndexed { i, der -> setCertificateEntry("anchor$i", factory.generateCertificate(der.inputStream())) }
            }
        }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(store)
    return tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
        ?: throw CertificateException("no X509TrustManager available")
}
