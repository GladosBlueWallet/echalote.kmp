package io.bluewallet.echalote

internal object CellCmd {
    const val PADDING = 0
    const val CREATE_FAST = 5
    const val CREATED_FAST = 6
    const val DESTROY = 4
    const val RELAY = 3
    const val RELAY_EARLY = 9
    const val VERSIONS = 7
    const val NETINFO = 8
    const val PADDING_NEGOTIATE = 12
    const val VPADDING = 128
    const val CERTS = 129
    const val AUTH_CHALLENGE = 130
}

internal object RelayCmd {
    const val BEGIN = 1
    const val DATA = 2
    const val END = 3
    const val CONNECTED = 4
    const val SENDME = 5
    const val EXTEND2 = 14
    const val EXTENDED2 = 15
    const val TRUNCATE = 8
    const val TRUNCATED = 9
    const val DROP = 10
    const val BEGIN_DIR = 13
}

internal data class RawCell(
    val circuitId: Int,
    val command: Int,
    val payload: ByteArray,
    val old: Boolean,
)

internal fun writeOldCell(circuitId: Int, command: Int, fragment: ByteArray): ByteArray {
    return if (command == CellCmd.VERSIONS) {
        val out = ByteArray(2 + 1 + 2 + fragment.size)
        val c = Cursor(out)
        c.writeU16(circuitId)
        c.writeU8(command)
        c.writeU16(fragment.size)
        c.write(fragment)
        out
    } else {
        val out = ByteArray(2 + 1 + PAYLOAD_LEN)
        val c = Cursor(out)
        c.writeU16(circuitId)
        c.writeU8(command)
        c.write(fragment)
        c.fill(0, c.remaining)
        out
    }
}

internal fun writeCell(circuitId: Int, command: Int, fragment: ByteArray): ByteArray {
    return if (command >= 128) {
        val out = ByteArray(4 + 1 + 2 + fragment.size)
        val c = Cursor(out)
        c.writeU32(circuitId)
        c.writeU8(command)
        c.writeU16(fragment.size)
        c.write(fragment)
        out
    } else {
        val out = ByteArray(4 + 1 + PAYLOAD_LEN)
        val c = Cursor(out)
        c.writeU32(circuitId)
        c.writeU8(command)
        c.write(fragment)
        c.fill(0, c.remaining)
        out
    }
}

internal fun tryReadOldCell(cursor: Cursor): RawCell? {
    if (cursor.remaining < 3) return null
    val start = cursor.offset
    val circuitId = cursor.readU16()
    val command = cursor.readU8()
    if (command == CellCmd.VERSIONS) {
        if (cursor.remaining < 2) {
            cursor.offset = start
            return null
        }
        val len = cursor.readU16()
        if (cursor.remaining < len) {
            cursor.offset = start
            return null
        }
        return RawCell(circuitId, command, cursor.read(len), old = true)
    }
    if (cursor.remaining < PAYLOAD_LEN) {
        cursor.offset = start
        return null
    }
    return RawCell(circuitId, command, cursor.read(PAYLOAD_LEN), old = true)
}

internal fun tryReadCell(cursor: Cursor): RawCell? {
    if (cursor.remaining < 5) return null
    val start = cursor.offset
    val circuitId = cursor.readU32()
    val command = cursor.readU8()
    if (command >= 128) {
        if (cursor.remaining < 2) {
            cursor.offset = start
            return null
        }
        val len = cursor.readU16()
        if (cursor.remaining < len) {
            cursor.offset = start
            return null
        }
        return RawCell(circuitId, command, cursor.read(len), old = false)
    }
    if (cursor.remaining < PAYLOAD_LEN) {
        cursor.offset = start
        return null
    }
    return RawCell(circuitId, command, cursor.read(PAYLOAD_LEN), old = false)
}

internal const val RELAY_HEAD_LEN = 1 + 2 + 2 + 4 + 2
internal const val RELAY_DATA_LEN = PAYLOAD_LEN - RELAY_HEAD_LEN

internal class Target(
    val relayidRsa: ByteArray,
    val forwardDigest: Sha1.Hasher,
    val backwardDigest: Sha1.Hasher,
    val forwardKey: Aes128Ctr128BEKey,
    val backwardKey: Aes128Ctr128BEKey,
) {
    var delivery = 1000
    var packageWindow = 1000
    val digests = ArrayList<ByteArray>()
}

internal fun encodeRelayPayload(
    rcommand: Int,
    streamId: Int,
    fragment: ByteArray,
    targets: List<Target>,
    @Suppress("UNUSED_PARAMETER") early: Boolean,
): ByteArray {
    val payload = ByteArray(PAYLOAD_LEN)
    val c = Cursor(payload)
    c.writeU8(rcommand)
    c.writeU16(0)
    c.writeU16(streamId)
    val digestOffset = c.offset
    c.writeU32(0)
    c.writeU16(fragment.size)
    c.write(fragment)
    c.fill(0, minOf(c.remaining, 4))
    if (c.remaining > 0) c.write(secureRandom(c.remaining))
    val exit = targets.last()
    exit.forwardDigest.update(payload)
    val digest20 = exit.forwardDigest.clone().finalize()
    if (rcommand == RelayCmd.DATA) {
        if (exit.packageWindow % 100 == 1) exit.digests += digest20
        exit.packageWindow--
    }
    payload.putU32be(digestOffset, (digest20.u8(0) shl 24) or (digest20.u8(1) shl 16) or (digest20.u8(2) shl 8) or digest20.u8(3))
    val mem = Memory(payload)
    for (i in targets.indices.reversed()) {
        targets[i].forwardKey.applyKeystream(mem)
    }
    return payload
}

internal data class DecodedRelay(
    val rcommand: Int,
    val streamId: Int,
    val fragment: ByteArray,
    val digest20: ByteArray,
)

internal fun decodeRelayPayload(payload: ByteArray, targets: List<Target>): DecodedRelay {
    val mem = Memory(payload.copyOf())
    for (target in targets) {
        target.backwardKey.applyKeystream(mem)
        val c = Cursor(mem.bytes)
        val rcommand = c.readU8()
        val recognised = c.readU16()
        if (recognised != 0) continue
        val streamId = c.readU16()
        val offset = c.offset
        val digest4 = c.read(4)
        mem.bytes.putU32be(offset, 0)
        val hasher = target.backwardDigest.clone()
        hasher.update(mem.bytes)
        val digest20 = hasher.finalize()
        val expect4 = digest20.copyOf(4)
        if (!equalBytes(digest4, expect4)) {
            digest4.copyInto(mem.bytes, offset)
            continue
        }
        target.backwardDigest.update(mem.bytes)
        val length = c.readU16()
        val data = c.read(length)
        return DecodedRelay(rcommand, streamId, data, digest20)
    }
    throw UnrecognisedRelayCellError()
}

internal fun versionsPayload(versions: IntArray): ByteArray {
    val out = ByteArray(versions.size * 2)
    val c = Cursor(out)
    for (v in versions) c.writeU16(v)
    return out
}

internal fun readVersions(payload: ByteArray): IntArray {
    val c = Cursor(payload)
    return IntArray(payload.size / 2) { c.readU16() }
}

internal fun netinfoPayload(): ByteArray {
    val other = TypedAddress(4, byteArrayOf(127, 0, 0, 1))
    val out = ByteArray(4 + other.size() + 1)
    val c = Cursor(out)
    c.writeU32(0)
    other.write(c)
    c.writeU8(0)
    return out
}

internal fun paddingNegotiateStop(): ByteArray {
    val out = ByteArray(6)
    val c = Cursor(out)
    c.writeU8(0)
    c.writeU8(1)
    c.writeU16(0)
    c.writeU16(0)
    return out
}

internal fun createFastPayload(material: ByteArray): ByteArray = material.copyOf(20)

internal fun readCreatedFast(payload: ByteArray): Pair<ByteArray, ByteArray> {
    val c = Cursor(payload)
    return c.read(20) to c.read(20)
}

internal fun destroyPayload(reason: Int): ByteArray = byteArrayOf(reason.toByte())

internal fun readDestroy(payload: ByteArray): Int = payload.u8(0)

internal fun extend2Payload(handshakeType: Int, links: List<ByteArray>, data: ByteArray): ByteArray {
    val linkBytes = concatBytes(*links.toTypedArray())
    val out = ByteArray(1 + linkBytes.size + 2 + 2 + data.size)
    val c = Cursor(out)
    c.writeU8(links.size)
    c.write(linkBytes)
    c.writeU16(handshakeType)
    c.writeU16(data.size)
    c.write(data)
    return out
}

internal fun extend2LinkIpv4(hostname: String, port: Int): ByteArray {
    val parts = hostname.split(".")
    val out = ByteArray(1 + 1 + 4 + 2)
    val c = Cursor(out)
    c.writeU8(0)
    c.writeU8(6)
    for (i in 0 until 4) c.writeU8(parts[i].toInt())
    c.writeU16(port)
    return out
}

internal fun extend2LinkIpv6(spec: String): ByteArray {
    val hostPort = spec.removePrefix("[").split("]")
    val ip = hostPort[0]
    val port = if (hostPort.size > 1) hostPort[1].removePrefix(":").toInt() else 0
    val groups = expandIpv6(ip)
    val out = ByteArray(1 + 1 + 16 + 2)
    val c = Cursor(out)
    c.writeU8(1)
    c.writeU8(18)
    for (g in groups) c.writeU16(g)
    c.writeU16(port)
    return out
}

internal fun extend2LinkLegacyId(fp: ByteArray): ByteArray {
    val out = ByteArray(1 + 1 + 20)
    val c = Cursor(out)
    c.writeU8(2)
    c.writeU8(20)
    c.write(fp)
    return out
}

internal fun extend2LinkModernId(fp: ByteArray): ByteArray {
    val out = ByteArray(1 + 1 + 32)
    val c = Cursor(out)
    c.writeU8(3)
    c.writeU8(32)
    c.write(fp)
    return out
}

private fun expandIpv6(ip: String): IntArray {
    val (left, right) = if (ip.contains("::")) {
        val parts = ip.split("::", limit = 2)
        parts[0].split(":").filter { it.isNotEmpty() } to parts.getOrElse(1) { "" }.split(":").filter { it.isNotEmpty() }
    } else {
        ip.split(":") to emptyList()
    }
    val out = IntArray(8)
    for (i in left.indices) out[i] = left[i].toInt(16)
    for (i in right.indices) out[8 - right.size + i] = right[i].toInt(16)
    return out
}

internal fun beginPayload(address: String, flags: Int): ByteArray {
    val bytes = address.encodeToByteArray()
    val out = ByteArray(bytes.size + 1 + 4)
    val c = Cursor(out)
    c.writeNulled(bytes)
    c.writeU32(flags)
    return out
}

internal fun sendmeCircuitPayload(digest20: ByteArray): ByteArray {
    val out = ByteArray(1 + 2 + 20)
    val c = Cursor(out)
    c.writeU8(1)
    c.writeU16(20)
    c.write(digest20)
    return out
}

internal fun readExtended2(fragment: ByteArray): ByteArray {
    val c = Cursor(fragment)
    val len = c.readU16()
    return c.read(len)
}

internal fun readSendmeCircuit(fragment: ByteArray): Pair<Int, ByteArray> {
    val c = Cursor(fragment)
    val version = c.readU8()
    if (c.remaining == 0) return version to ByteArray(0)
    val len = c.readU16()
    return version to c.read(len)
}

internal fun readRelayEnd(fragment: ByteArray): RelayEndReason {
    val c = Cursor(fragment)
    val id = c.readU8()
    return if (id == 4 && c.remaining >= 8) {
        RelayEndReasonExitPolicy(Address4.read(c), currentEpochMillis() + c.readU32().toLong() * 1000)
    } else {
        RelayEndReasonOther(id)
    }
}

internal object DestroyReasons {
    const val NONE = 0
}

internal object BeginFlags {
    const val IPV6_OK = 0
    const val IPV4_NOT_OK = 1
    const val IPV6_PREFER = 2
}

internal fun beginFlagsPreferred(): Int {
    var flags = 0
    flags = flags or (1 shl BeginFlags.IPV6_OK)
    flags = flags or (1 shl BeginFlags.IPV6_PREFER)
    return flags
}
