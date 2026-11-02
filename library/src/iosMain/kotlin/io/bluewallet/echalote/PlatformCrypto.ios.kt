package io.bluewallet.echalote

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFMutableDictionaryRef
import platform.CoreFoundation.CFNumberCreate
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.kCFNumberIntType
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyKeyExchangeResult
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateEncryptedData
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateWithData
import platform.Security.SecKeyRef
import platform.Security.kSecAttrKeyClass
import platform.Security.kSecAttrKeyClassPublic
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrKeyTypeRSA
import platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard
import platform.Security.kSecKeyAlgorithmRSAEncryptionRaw

/*
 * Security.framework versions of the two hot public-key operations. Pure-Kotlin BigNat / P256
 * took 1-4 s per authority certificate and ~1 s per consensus signature on the CI simulator.
 * Any failure returns null so the caller falls back to the pure-Kotlin code.
 */

/**
 * `signature^exponent mod modulus` via kSecKeyAlgorithmRSAEncryptionRaw on an RSA public key
 * built from a DER RSAPublicKey. Raw "encryption" with the public key is exactly the RSA
 * public operation; the caller has already checked `signature < modulus`.
 */
@OptIn(ExperimentalForeignApi::class)
internal actual fun platformRsaPublicOp(
    signature: ByteArray,
    exponent: ByteArray,
    modulus: ByteArray,
    outLen: Int,
): ByteArray? =
    cfOperation {
        val n = stripLeadingZeros(modulus)
        require(n.isNotEmpty() && signature.isNotEmpty() && signature.size <= n.size)
        // Raw RSA needs the input to be exactly the modulus length.
        val input = if (signature.size == n.size) signature else ByteArray(n.size - signature.size) + signature
        val der = derSequence(derInteger(n) + derInteger(stripLeadingZeros(exponent)))
        val attrs = dict()
        CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA)
        CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic)
        val key = key(der, attrs)
        val inData = data(input)
        val out = own(withCfError { SecKeyCreateEncryptedData(key, kSecKeyAlgorithmRSAEncryptionRaw, inData, it) })
        unsignedFixed(cfBytes(out), outLen)
    }

/** Ephemeral P-256 ECDH: SecKeyCreateRandomKey + SecKeyCopyKeyExchangeResult (standard = shared X). */
@OptIn(ExperimentalForeignApi::class)
internal actual fun platformP256Ecdh(peerUncompressed: ByteArray): Pair<ByteArray, ByteArray>? =
    cfOperation {
        require(isUncompressedP256(peerUncompressed))
        val genAttrs = dict()
        val bitsNum =
            own(
                memScoped {
                    val bits = alloc<IntVar>().apply { value = 256 }
                    CFNumberCreate(null, kCFNumberIntType, bits.ptr)
                },
            )
        CFDictionarySetValue(genAttrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(genAttrs, kSecAttrKeySizeInBits, bitsNum)
        val private = own(withCfError { SecKeyCreateRandomKey(genAttrs, it) })
        val public = own(SecKeyCopyPublicKey(private))
        val ours = cfBytes(own(withCfError { SecKeyCopyExternalRepresentation(public, it) }))
        require(isUncompressedP256(ours))

        val peerAttrs = dict()
        CFDictionarySetValue(peerAttrs, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(peerAttrs, kSecAttrKeyClass, kSecAttrKeyClassPublic)
        val peer = key(peerUncompressed, peerAttrs)
        val params = dict()
        val secret =
            cfBytes(
                own(withCfError { SecKeyCopyKeyExchangeResult(private, kSecKeyAlgorithmECDHKeyExchangeStandard, peer, params, it) }),
            )
        require(secret.size == 32)
        ours to secret
    }

private fun isUncompressedP256(point: ByteArray): Boolean = point.size == 65 && point[0] == 0x04.toByte()

/** Runs [block], releasing every CF object it [CfScope.own]s; any failure yields null. */
@OptIn(ExperimentalForeignApi::class)
private inline fun <T> cfOperation(block: CfScope.() -> T): T? {
    val scope = CfScope()
    return try {
        scope.block()
    } catch (_: Exception) {
        null
    } finally {
        scope.releaseAll()
    }
}

@OptIn(ExperimentalForeignApi::class)
private class CfScope {
    private val owned = ArrayList<CPointer<*>>()

    /** Takes ownership of a +1 CF reference; a null (failed) call aborts the operation. */
    fun <T : CPointer<*>> own(ref: T?): T {
        checkNotNull(ref) { "Security.framework call failed" }
        owned += ref
        return ref
    }

    fun releaseAll() = owned.forEach { CFRelease(it) }

    fun dict(): CFMutableDictionaryRef = own(CFDictionaryCreateMutable(null, 0, kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr))

    fun data(bytes: ByteArray): CFDataRef = own(bytes.usePinned { pinned -> CFDataCreate(null, pinned.addressOf(0).reinterpret(), bytes.size.convert()) })

    fun key(
        keyData: ByteArray,
        attrs: CFMutableDictionaryRef,
    ): SecKeyRef {
        val data = data(keyData)
        return own(withCfError { SecKeyCreateWithData(data, attrs, it) })
    }
}

/** Calls [block] with a CFErrorRef out-pointer and releases any error it reports. */
@OptIn(ExperimentalForeignApi::class)
private inline fun <T> withCfError(block: (CPointer<CFErrorRefVar>) -> T?): T? =
    memScoped {
        val err = alloc<CFErrorRefVar>()
        block(err.ptr).also { err.value?.let { e -> CFRelease(e) } }
    }

@OptIn(ExperimentalForeignApi::class)
private fun cfBytes(data: CFDataRef): ByteArray {
    val len = CFDataGetLength(data).toInt()
    val ptr = if (len > 0) CFDataGetBytePtr(data) else null
    return ptr?.readBytes(len) ?: ByteArray(0)
}

private fun stripLeadingZeros(b: ByteArray): ByteArray {
    var i = 0
    while (i < b.size - 1 && b[i] == 0.toByte()) i++
    return if (i == 0) b else b.copyOfRange(i, b.size)
}

private fun derLength(len: Int): ByteArray =
    when {
        len < 0x80 -> byteArrayOf(len.toByte())
        len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
        len < 0x10000 -> byteArrayOf(0x82.toByte(), (len shr 8).toByte(), len.toByte())
        else -> byteArrayOf(0x83.toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte())
    }

/** DER INTEGER for an unsigned big-endian value (adds a 0x00 pad when the top bit is set). */
private fun derInteger(unsigned: ByteArray): ByteArray {
    val body = if (unsigned[0].toInt() and 0x80 != 0) byteArrayOf(0) + unsigned else unsigned
    return byteArrayOf(0x02) + derLength(body.size) + body
}

private fun derSequence(content: ByteArray): ByteArray = byteArrayOf(0x30) + derLength(content.size) + content
