package io.bluewallet.echalote

import android.net.http.X509TrustManagerExtensions
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
 * Verifies the chain with the platform trust manager through [X509TrustManagerExtensions],
 * which applies the app's Network Security Config for [host] (trust anchors, pins, user CA
 * policy). The host name itself is checked in common code by [verifyWebPkiChain].
 */
internal actual suspend fun verifyServerChain(
    chainDer: List<ByteArray>,
    host: String,
) = withContext(Dispatchers.IO) {
    val factory = CertificateFactory.getInstance("X.509")
    val chain = chainDer.map { factory.generateCertificate(it.inputStream()) as X509Certificate }.toTypedArray()
    X509TrustManagerExtensions(platformTrustManager).checkServerTrusted(chain, SERVER_AUTH_TYPE, host)
    Unit
}

private val platformTrustManager: X509TrustManager by lazy {
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    tmf.init(null as KeyStore?)
    tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
        ?: throw CertificateException("no X509TrustManager available")
}
