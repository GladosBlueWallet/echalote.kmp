package io.bluewallet.echalote

object Console {
    var debugging = false
    fun log(vararg params: Any?) {
        if (debugging) println(params.joinToString(" "))
    }
    fun debug(vararg params: Any?) {
        if (debugging) println(params.joinToString(" "))
    }
    fun error(vararg params: Any?) {
        if (debugging) println(params.joinToString(" "))
    }
    fun warn(vararg params: Any?) {
        if (debugging) println(params.joinToString(" "))
    }
}

const val HASH_LEN = 20
const val KEY_LEN = 16
const val PAYLOAD_LEN = 509

class Unimplemented : Exception("Unimplemented")
class InvalidTorStateError : Exception("Invalid Tor state")
class InvalidTorVersionError : Exception("Invalid Tor version")
class InvalidCellError : Exception("Invalid cell")
class InvalidCommandError : Exception("Invalid command")
class ExpectedCircuitError : Exception("Expected a circuit")
class UnexpectedCircuitError : Exception("Unexpected a circuit")
class InvalidRelayCommandError : Exception("Invalid relay command")
class UnknownStreamError : Exception("Unknown stream")
class ExpectedStreamError : Exception("Expected a stream")
class UnexpectedStreamError : Exception("Unexpected a stream")
class InvalidRelayCellDigestError : Exception("Invalid RELAY cell digest")
class InvalidRelaySendmeCellDigestError : Exception("Invalid RELAY_SENDME cell digest")
class UnrecognisedRelayCellError : Exception("Unrecognised relay cell")
class InvalidKdfKeyHashError : Exception("Invalid KDF key hash")
class InvalidNtorAuthError : Exception("Invalid Ntor auth")
class DestroyedError(val reasonCode: Int) : Exception("Circuit destroyed")
class RelayEndedError(val reason: RelayEndReason) : Exception("Relay ended")
class UnknownAddressType(val type: Int) : Exception("Unknown address type $type")
class DuplicatedCertError : Exception("Duplicated certificate")
class UnknownCertError : Exception("Unknown certificate")
class ExpectedCertError : Exception("Expected a certificate")
class ExpiredCertError : Exception("Expired certificate")
class PrematureCertError : Exception("Premature certificate")
class InvalidSignatureError : Exception("Invalid certificate signature")
class InvalidCertError : Exception("Invalid certificate")
class UnknownCertExtensionError(val type: Int) : Exception("Unknown certificate extension $type")

sealed class RelayEndReason {
    abstract val id: Int
    abstract fun size(): Int
    abstract fun write(cursor: Cursor)
}

class RelayEndReasonOther(override val id: Int) : RelayEndReason() {
    override fun size() = 0
    override fun write(cursor: Cursor) {}
}

class RelayEndReasonExitPolicy(
    val address: Address4,
    val ttlEpochMillis: Long,
) : RelayEndReason() {
    override val id: Int = 4
    override fun size() = address.size() + 4
    override fun write(cursor: Cursor) {
        address.write(cursor)
        val ttlv = ((ttlEpochMillis - currentEpochMillis()) / 1000).toInt()
        cursor.writeU32(ttlv)
    }
}

class Address4(val address: String) {
    fun size() = 4
    fun write(cursor: Cursor) {
        val parts = address.split(".")
        for (i in 0 until 4) cursor.writeU8(parts[i].toInt())
    }
    companion object {
        fun read(cursor: Cursor): Address4 {
            val parts = Array(4) { cursor.readU8().toString() }
            return Address4(parts.joinToString("."))
        }
    }
}

class Address6(val address: String) {
    fun size() = 16
    companion object {
        fun read(cursor: Cursor): Address6 {
            val parts = Array(8) { cursor.readU16().toString(16) }
            return Address6("[${parts.joinToString(":")}]")
        }
    }
}

class TypedAddress(val type: Int, val value: ByteArray) {
    fun size() = 1 + 1 + value.size
    fun write(cursor: Cursor) {
        cursor.writeU8(type)
        cursor.writeU8(value.size)
        cursor.write(value)
    }
    companion object {
        fun read(cursor: Cursor): TypedAddress {
            val type = cursor.readU8()
            val length = cursor.readU8()
            return TypedAddress(type, cursor.read(length))
        }
    }
}

fun initBundledCrypto() {}
