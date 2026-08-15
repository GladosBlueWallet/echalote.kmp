package org.hazae41.echalote

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CircuitLifecycleTest {
    @Test
    fun destroyMarksCircuitClosedAndDropsStreams() {
        val tor = SecretTorClientDuplex()
        try {
            val circ = SecretCircuit(1, tor)
            tor.circuits[1] = circ
            val stream = SecretTorStreamDuplex("external", 7, circ)
            circ.streams[7] = stream
            circ.onCloseOrError(DestroyedError(11))
            assertTrue(circ.closed is DestroyedError)
            assertEquals(11, (circ.closed as DestroyedError).reasonCode)
            assertTrue(circ.streams.isEmpty())
            assertTrue(!tor.circuits.containsKey(1))
        } finally {
            tor.close()
        }
    }

    @Test
    fun destroyIsIdempotent() {
        val tor = SecretTorClientDuplex()
        try {
            val circ = SecretCircuit(2, tor)
            tor.circuits[2] = circ
            circ.onCloseOrError(DestroyedError(1))
            circ.onCloseOrError(DestroyedError(2))
            assertEquals(1, (circ.closed as DestroyedError).reasonCode)
        } finally {
            tor.close()
        }
    }
}
