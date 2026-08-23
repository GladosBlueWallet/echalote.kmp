package io.bluewallet.echalote

data class Consensus(
    val type: String? = null,
    val version: Int = 0,
    val status: String? = null,
    val method: Int = 0,
    val microdescs: List<MicrodescHead> = emptyList(),
    val authorities: List<Authority> = emptyList(),
    val signatures: List<ConsensusSignature> = emptyList(),
    val preimage: String? = null,
    val knownFlags: List<String> = emptyList(),
)

data class Authority(
    val nickname: String,
    val identity: String,
    val hostname: String,
    val ipaddress: String,
    val dirport: Int,
    val orport: Int,
    val contact: String,
    val digest: String,
)

data class ConsensusSignature(
    val algorithm: String,
    val identity: String,
    val signingKeyDigest: String,
    val signature: String,
)

data class MicrodescHead(
    val nickname: String,
    val identity: String,
    val date: String,
    val hour: String,
    val hostname: String,
    val orport: Int,
    val dirport: Int,
    val ipv6: String? = null,
    val microdesc: String,
    val flags: List<String>,
    val version: String? = null,
    val entries: Map<String, String>,
    val bandwidth: Map<String, String>,
)

data class MicrodescBody(
    val onionKey: String,
    val ntorOnionKey: String,
    val idEd25519: String,
)

data class Microdesc(
    val head: MicrodescHead,
    val onionKey: String,
    val ntorOnionKey: String,
    val idEd25519: String,
) {
    val nickname get() = head.nickname
    val identity get() = head.identity
    val hostname get() = head.hostname
    val orport get() = head.orport
    val dirport get() = head.dirport
    val ipv6 get() = head.ipv6
    val flags get() = head.flags
}

object ConsensusParser {
    fun parseOrThrow(text: String): Consensus {
        val lines = text.split("\n")
        var type: String? = null
        var version = 0
        var status: String? = null
        var method = 0
        val knownFlags = ArrayList<String>()
        val authorities = ArrayList<Authority>()
        val microdescs = ArrayList<MicrodescHead>()
        val signatures = ArrayList<ConsensusSignature>()
        var preimage: String? = null
        var i = 0
        while (i < lines.size) {
            val line = lines[i]
            when {
                line.startsWith("network-status-version ") -> {
                    val parts = line.split(" ")
                    version = parts.getOrNull(1)?.toIntOrNull() ?: 0
                    type = parts.getOrNull(2)
                }
                line.startsWith("vote-status ") -> status = line.split(" ").getOrNull(1)
                line.startsWith("consensus-method ") -> method = line.split(" ").getOrNull(1)?.toIntOrNull() ?: 0
                line.startsWith("known-flags ") -> {
                    knownFlags.clear()
                    knownFlags += line.split(" ").drop(1)
                }
                line == "directory-footer" -> {
                    i++
                    while (i < lines.size) {
                        val fl = lines[i]
                        if (fl.startsWith("directory-signature ")) {
                            if (preimage == null) {
                                preimage = lines.take(i).joinToString("\n") + "\ndirectory-signature "
                            }
                            val parts = fl.split(" ")
                            i++
                            val sig = readBlock(lines, i, "-----BEGIN SIGNATURE-----", "-----END SIGNATURE-----")
                                ?: throw IllegalArgumentException("Missing BEGIN SIGNATURE")
                            i = sig.second
                            signatures += ConsensusSignature(
                                algorithm = parts.getOrNull(1) ?: "",
                                identity = parts.getOrNull(2) ?: "",
                                signingKeyDigest = parts.getOrNull(3) ?: "",
                                signature = sig.first,
                            )
                        }
                        i++
                    }
                    break
                }
                line.startsWith("r ") -> {
                    val parts = line.split(" ")
                    var nickname = parts.getOrNull(1) ?: throw IllegalArgumentException("Missing nickname")
                    var identity = parts.getOrNull(2) ?: throw IllegalArgumentException("Missing identity")
                    var date = parts.getOrNull(3) ?: throw IllegalArgumentException("Missing date")
                    var hour = parts.getOrNull(4) ?: throw IllegalArgumentException("Missing hour")
                    var hostname = parts.getOrNull(5) ?: throw IllegalArgumentException("Missing hostname")
                    var orport = parts.getOrNull(6)?.toIntOrNull() ?: throw IllegalArgumentException("Missing orport")
                    var dirport = parts.getOrNull(7)?.toIntOrNull() ?: throw IllegalArgumentException("Missing dirport")
                    var ipv6: String? = null
                    var microdesc: String? = null
                    var flags: List<String>? = null
                    var ver: String? = null
                    var entries: Map<String, String>? = null
                    var bandwidth: Map<String, String>? = null
                    i++
                    while (i < lines.size) {
                        val sl = lines[i]
                        when {
                            sl.startsWith("dir-source ") || sl.startsWith("r ") || sl == "directory-footer" -> {
                                i--
                                break
                            }
                            sl.startsWith("a ") -> ipv6 = sl.split(" ").getOrNull(1)
                            sl.startsWith("m ") -> microdesc = sl.split(" ").getOrNull(1)
                            sl.startsWith("s ") -> flags = sl.split(" ").drop(1)
                            sl.startsWith("v ") -> ver = sl.substring(2)
                            sl.startsWith("pr ") -> {
                                entries = sl.split(" ").drop(1).associate {
                                    val eq = it.indexOf('=')
                                    if (eq < 0) it to "" else it.substring(0, eq) to it.substring(eq + 1)
                                }
                            }
                            sl.startsWith("w ") -> {
                                bandwidth = sl.split(" ").drop(1).associate {
                                    val eq = it.indexOf('=')
                                    if (eq < 0) it to "" else it.substring(0, eq) to it.substring(eq + 1)
                                }
                            }
                        }
                        i++
                    }
                    microdescs += MicrodescHead(
                        nickname = nickname,
                        identity = identity,
                        date = date,
                        hour = hour,
                        hostname = hostname,
                        orport = orport,
                        dirport = dirport,
                        ipv6 = ipv6,
                        microdesc = microdesc ?: throw IllegalArgumentException("Missing microdesc"),
                        flags = flags ?: throw IllegalArgumentException("Missing flags"),
                        version = ver,
                        entries = entries ?: throw IllegalArgumentException("Missing entries"),
                        bandwidth = bandwidth ?: throw IllegalArgumentException("Missing bandwidth"),
                    )
                }
            }
            i++
        }
        return Consensus(
            type = type,
            version = version,
            status = status,
            method = method,
            microdescs = microdescs,
            authorities = authorities,
            signatures = signatures,
            preimage = preimage,
            knownFlags = knownFlags,
        )
    }

    fun parseMicrodescOrThrow(text: String): List<MicrodescBody> {
        val lines = text.split("\n")
        val items = ArrayList<MicrodescBody>()
        var i = 0
        while (i < lines.size) {
            if (lines[i] == "onion-key") {
                i++
                val onionKey = readBlock(lines, i, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")
                    ?: throw IllegalArgumentException("Missing BEGIN RSA PUBLIC KEY")
                i = onionKey.second
                var ntor: String? = null
                var idEd: String? = null
                i++
                while (i < lines.size) {
                    when {
                        lines[i] == "onion-key" -> {
                            i--
                            break
                        }
                        lines[i].startsWith("ntor-onion-key ") -> ntor = lines[i].split(" ").getOrNull(1)
                        lines[i].startsWith("id ed25519 ") -> idEd = lines[i].split(" ").getOrNull(2)
                    }
                    i++
                }
                items += MicrodescBody(
                    onionKey = onionKey.first,
                    ntorOnionKey = ntor ?: throw IllegalArgumentException("Missing ntor-onion-key"),
                    idEd25519 = idEd ?: throw IllegalArgumentException("Missing id ed25519"),
                )
            }
            i++
        }
        return items
    }

    private fun readBlock(lines: List<String>, start: Int, begin: String, end: String): Pair<String, Int>? {
        var i = start
        if (i >= lines.size || lines[i] != begin) return null
        val text = StringBuilder()
        i++
        while (i < lines.size) {
            if (lines[i] == end) return text.toString() to i
            text.append(lines[i])
            i++
        }
        throw IllegalArgumentException("Missing $end")
    }
}
