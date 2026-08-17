package io.bluewallet.echalote

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BuildExitCircuitTest {
    private fun fakeCircuit(id: Int) = Circuit(id)

    @Test
    fun treatsMicrodescTimeoutAndDestroyedAsTransient() {
        assertTrue(isTransientCircuitError(Exception("no microdesc URL succeeded")))
        assertTrue(isTransientCircuitError(Exception("The operation timed out.")))
        assertTrue(isTransientCircuitError(Exception("Circuit destroyed")))
        assertTrue(isTransientCircuitError(Exception("consensus fetch failed")))
    }

    @Test
    fun doesNotTreatUnrelatedErrorsAsTransient() {
        assertFalse(isTransientCircuitError(Exception("peer refused")))
        assertFalse(isTransientCircuitError(Exception("disposed")))
    }

    @Test
    fun retriesTransientBuildOnceFailuresUpToAttempts() = runTest {
        var calls = 0
        val circuit = fakeCircuit(1)
        val client = TorClientDuplex()
        val result = buildExitCircuit(
            client,
            options = BuildExitCircuitOptions(
                attempts = 3,
                circuitRace = 1,
                buildOnce = { _, _, _ ->
                    calls++
                    if (calls < 3) throw Exception("no microdesc URL succeeded")
                    circuit
                },
            ),
        )
        assertEquals(circuit, result)
        assertEquals(3, calls)
    }

    @Test
    fun doesNotRetryNonTransientErrors() = runTest {
        var calls = 0
        val client = TorClientDuplex()
        val ex = assertFails {
            buildExitCircuit(
                client,
                options = BuildExitCircuitOptions(
                    attempts = 5,
                    circuitRace = 1,
                    buildOnce = { _, _, _ ->
                        calls++
                        throw Exception("peer refused")
                    },
                ),
            )
        }
        assertTrue(ex.message?.contains("peer refused") == true)
        assertEquals(1, calls)
    }

    @Test
    fun racesParallelBuildsAndClosesLosers() = runTest {
        val client = TorClientDuplex()
        val closed = ArrayList<Int>()
        var started = 0
        val result = buildExitCircuit(
            client,
            options = BuildExitCircuitOptions(
                attempts = 1,
                circuitRace = 2,
                buildOnce = { _, _, _ ->
                    val id = ++started
                    if (id == 1) delay(80)
                    object : Circuit(id) {
                        override suspend fun close() {
                            closed += id
                        }
                    }
                },
            ),
        )
        assertEquals(2, result.id)
        delay(120)
        assertTrue(closed.contains(1))
    }

    @Test
    fun rejectsNonPositiveCircuitRace() = runTest {
        val client = TorClientDuplex()
        val ex = assertFails {
            buildExitCircuit(
                client,
                options = BuildExitCircuitOptions(
                    circuitRace = 0,
                    buildOnce = { _, _, _ -> fakeCircuit(1) },
                ),
            )
        }
        assertTrue(ex.message?.contains("positive integer", ignoreCase = true) == true)
    }
}

class RaceFirstCircuitTest {
    @Test
    fun rejectsWhenParentAbortsEvenIfBuilderIgnoresSignal() = runTest {
        val parent = Abort()
        supervisorScope {
            val pending = async {
                raceFirstCircuit(
                    1,
                    build = {
                        kotlinx.coroutines.CompletableDeferred<Circuit>().await()
                    },
                    signal = parent,
                )
            }
            parent.abort(Exception("parent cancelled"))
            val ex = runCatching { pending.await() }.exceptionOrNull()
            assertTrue(ex != null && ex.message?.contains("parent cancelled") == true)
        }
    }

    @Test
    fun doesNotAbortTheWinnerSignalAfterSettle() = runTest {
        val winnerSignals = ArrayList<Abort>()
        val circuit = raceFirstCircuit(
            2,
            build = { signal ->
                winnerSignals += signal
                if (winnerSignals.size == 1) {
                    delay(50)
                    if (signal.aborted) throw signal.reason ?: Exception("aborted")
                }
                Circuit(winnerSignals.size)
            },
        )
        assertEquals(2, circuit.id)
        assertFalse(winnerSignals[1].aborted)
    }
}
