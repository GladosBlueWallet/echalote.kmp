package io.bluewallet.echalote

import kotlinx.coroutines.launch

private const val STREAM_SENDME_BUFFER = 10 * RELAY_DATA_LEN

internal class SecretTorStreamDuplex(
    val type: String,
    val id: Int,
    val circuit: SecretCircuit,
) {
    val duplex = ChannelDuplex()
    val connected = kotlinx.coroutines.CompletableDeferred<Unit>()
    var delivery = 500
    var packageWindow = 500
    private var bufferedBytes = 0
    private var sendmesOwed = 0
    private var cleaned = false
    private val offs = ArrayList<() -> Unit>()

    init {
        duplex.onWrite = { bytes ->
            for (chunk in Cursor(bytes).split(RELAY_DATA_LEN)) {
                circuit.tor.sendRelay(circuit, RelayCmd.DATA, id, chunk)
            }
        }
        duplex.onRead = { n ->
            val owed = circuit.tor.gate.withLock {
                bufferedBytes = (bufferedBytes - n).coerceAtLeast(0)
                takeOwedSendmes()
            }
            if (owed > 0) launchStreamSendmes(owed)
        }
        duplex.onClose = {
            if (circuit.closed == null) {
                val end = byteArrayOf(6)
                circuit.tor.scope.launch {
                    try {
                        circuit.tor.sendRelay(circuit, RelayCmd.END, id, end)
                    } catch (_: Throwable) {
                    }
                }
                circuit.tor.gate.withLock {
                    if (packageWindow > 0) packageWindow--
                }
            }
            cleanup()
        }
        offs +=
            circuit.tor.relayConnected.on { (circ, stream) ->
                if (circ === circuit && stream === this) {
                    connected.complete(Unit)
                }
            }
        offs +=
            circuit.tor.relayEnd.on { (circ, pair) ->
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
        offs +=
            circuit.tor.destroyed.on { (circ, code) ->
                if (circ === circuit) fail(DestroyedError(code))
            }
    }

    suspend fun waitConnected(abort: Abort?) {
        withAbort(abort) { connected.await() }
    }

    /** Must run on the cell reader. A per-cell launch can reorder RELAY_DATA. */
    suspend fun onIncomingData(data: ByteArray) {
        val owed =
            circuit.tor.gate.withLock {
                delivery--
                bufferedBytes += data.size
                if (delivery == 450) {
                    delivery = 500
                    sendmesOwed++
                }
                takeOwedSendmes()
            }
        duplex.enqueue(data)
        if (owed > 0) launchStreamSendmes(owed)
    }

    private fun takeOwedSendmes(): Int {
        if (sendmesOwed == 0 || bufferedBytes >= STREAM_SENDME_BUFFER) return 0
        val n = sendmesOwed
        sendmesOwed = 0
        return n
    }

    private fun launchStreamSendmes(count: Int) {
        circuit.tor.scope.launch {
            repeat(count) {
                try {
                    circuit.tor.sendRelay(circuit, RelayCmd.SENDME, id, ByteArray(0))
                } catch (_: Throwable) {
                }
            }
        }
    }

    fun fail(reason: Throwable?) {
        val err = reason ?: Exception("tor connection closed")
        if (!connected.isCompleted) connected.completeExceptionally(err)
        if (reason != null) {
            duplex.error(reason)
        } else {
            // Close here. Launching onto the client scope loses the wakeup when close() cancels that scope.
            duplex.close()
        }
        cleanup()
    }

    private fun cleanup() {
        val run =
            circuit.tor.gate.withLock {
                if (cleaned) {
                    false
                } else {
                    cleaned = true
                    circuit.streams.remove(id)
                    true
                }
            }
        if (!run) return
        circuit.tor.wakeWindowWaiters()
        if (!connected.isCompleted) connected.completeExceptionally(Exception("tor stream closed"))
        for (off in offs) {
            try {
                off()
            } catch (_: Throwable) {
            }
        }
        offs.clear()
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
