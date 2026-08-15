package org.hazae41.echalote

import kotlinx.coroutines.launch

internal class SecretTorStreamDuplex(
    val type: String,
    val id: Int,
    val circuit: SecretCircuit,
) {
    val duplex = ChannelDuplex()
    val connected = kotlinx.coroutines.CompletableDeferred<Unit>()
    var delivery = 500
    var packageWindow = 500
    private var cleaned = false
    private val offs = ArrayList<() -> Unit>()

    init {
        duplex.onWrite = { bytes ->
            for (chunk in Cursor(bytes).split(RELAY_DATA_LEN)) {
                val payload = encodeRelayPayload(
                    RelayCmd.DATA, id, chunk, circuit.targets, early = false,
                )
                circuit.tor.send(writeCell(circuit.id, CellCmd.RELAY, payload))
                packageWindow--
            }
        }
        duplex.onClose = {
            if (circuit.closed == null) {
                val end = byteArrayOf(6)
                circuit.tor.scope.launch {
                    try {
                        val payload = encodeRelayPayload(RelayCmd.END, id, end, circuit.targets, early = false)
                        circuit.tor.send(writeCell(circuit.id, CellCmd.RELAY, payload))
                    } catch (_: Throwable) {
                    }
                }
                packageWindow--
            }
            cleanup()
        }
        offs += circuit.tor.relayConnected.on { (circ, stream) ->
            if (circ === circuit && stream === this) {
                connected.complete(Unit)
            }
        }
        offs += circuit.tor.relayData.on { (circ, pair) ->
            val (stream, data) = pair
            if (circ !== circuit || stream !== this) return@on
            delivery--
            if (delivery == 450) {
                delivery = 500
                val payload = encodeRelayPayload(
                    RelayCmd.SENDME, id, ByteArray(0), circuit.targets, early = false,
                )
                circuit.tor.scope.launch {
                    try {
                        circuit.tor.send(writeCell(circuit.id, CellCmd.RELAY, payload))
                    } catch (_: Throwable) {
                    }
                }
            }
            circuit.tor.scope.launch {
                try {
                    duplex.enqueue(data)
                } catch (_: Throwable) {
                }
            }
        }
        offs += circuit.tor.relayEnd.on { (circ, pair) ->
            val (stream, reason) = pair
            if (circ !== circuit || stream !== this) return@on
            if (reason.id == 6) {
                circuit.tor.scope.launch { duplex.close() }
            } else {
                fail(RelayEndedError(reason))
            }
        }
        offs += circuit.tor.closeEvent.on { fail(null) }
        offs += circuit.tor.errorEvent.on { fail(it) }
        offs += circuit.tor.destroyed.on { (circ, code) ->
            if (circ === circuit) fail(DestroyedError(code))
        }
    }

    suspend fun waitConnected(abort: Abort?) {
        withAbort(abort) { connected.await() }
    }

    fun fail(reason: Throwable?) {
        if (reason != null) duplex.error(reason) else {
            circuit.tor.scope.launch { duplex.close() }
        }
        cleanup()
    }

    private fun cleanup() {
        if (cleaned) return
        cleaned = true
        for (off in offs) {
            try {
                off()
            } catch (_: Throwable) {
            }
        }
        offs.clear()
        circuit.streams.remove(id)
    }

    fun asPublic(onClose: () -> Unit): TorStreamDuplex =
        TorStreamDuplex(duplex) {
            try {
                duplex.close()
            } catch (_: Throwable) {
            }
            onClose()
        }
}
