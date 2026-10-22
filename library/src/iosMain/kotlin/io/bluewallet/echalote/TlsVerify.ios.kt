package io.bluewallet.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.CoreFoundation.CFArrayAppendValue
import platform.CoreFoundation.CFArrayCreateMutable
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFMutableArrayRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeArrayCallBacks
import platform.Security.SecCertificateCreateWithData
import platform.Security.SecPolicyCreateSSL
import platform.Security.SecTrustCreateWithCertificates
import platform.Security.SecTrustEvaluateWithError
import platform.Security.SecTrustRefVar
import platform.Security.SecTrustSetNetworkFetchAllowed
import platform.Security.errSecSuccess

/**
 * Verifies with Security.framework: an SSL server policy for [host] evaluated by
 * SecTrustEvaluateWithError (system trust store, CT rules, host name). Network fetching
 * (AIA / OCSP) is disabled so nothing leaves the device outside Tor; evaluation still runs
 * off the main thread since SecTrustEvaluateWithError is blocking.
 */
@OptIn(ExperimentalForeignApi::class)
internal actual suspend fun verifyServerChain(
    chainDer: List<ByteArray>,
    host: String,
) = withContext(Dispatchers.IO) {
    val owned = ArrayList<CFTypeRef?>()
    try {
        val certs = certificateArray(chainDer, owned)
        // A null host would make SecPolicyCreateSSL skip the host name check entirely.
        val hostRef =
            CFStringCreateWithCString(null, host, kCFStringEncodingUTF8)
                ?: rejectCertificate("TLS: cannot encode host name $host")
        owned += hostRef
        val policy = SecPolicyCreateSSL(true, hostRef) ?: rejectCertificate("SecPolicyCreateSSL failed")
        owned += policy
        memScoped {
            val trustVar = alloc<SecTrustRefVar>()
            val status = SecTrustCreateWithCertificates(certs, policy, trustVar.ptr)
            val trust = trustVar.value
            if (status != errSecSuccess || trust == null) rejectCertificate("SecTrustCreateWithCertificates failed: $status")
            owned += trust
            // Never let evaluation reach the clear network (AIA / OCSP) from a Tor library.
            if (SecTrustSetNetworkFetchAllowed(trust, false) != errSecSuccess) rejectCertificate("cannot disable SecTrust network fetch")
            val error = alloc<CFErrorRefVar>()
            if (!SecTrustEvaluateWithError(trust, error.ptr)) {
                val code = error.value?.let { err -> CFErrorGetCode(err).also { CFRelease(err) } }
                rejectCertificate("TLS certificate for $host rejected by SecTrust (error $code)")
            }
        }
    } finally {
        owned.forEach { ref -> ref?.let { CFRelease(it) } }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun certificateArray(
    ders: List<ByteArray>,
    owned: MutableList<CFTypeRef?>,
): CFMutableArrayRef {
    val array =
        CFArrayCreateMutable(null, ders.size.convert(), kCFTypeArrayCallBacks.ptr)
            ?: rejectCertificate("CFArrayCreateMutable failed")
    owned += array
    for (der in ders) {
        if (der.isEmpty()) rejectCertificate("empty certificate")
        val data =
            der.usePinned { pinned -> CFDataCreate(null, pinned.addressOf(0).reinterpret(), der.size.convert()) }
                ?: rejectCertificate("CFDataCreate failed")
        owned += data
        val cert = SecCertificateCreateWithData(null, data) ?: rejectCertificate("unparseable certificate")
        owned += cert
        CFArrayAppendValue(array, cert)
    }
    return array
}
