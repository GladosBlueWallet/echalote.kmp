package io.bluewallet.echalote

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class ExitDialerCircuitReuseTest {
    private class RecordingCircuit(
        id: Int,
    ) : Circuit(id) {
        var openCount = 0
        var closeCount = 0
        var failOpen: Throwable? = null
        var dead = false

        override val isClosed: Boolean get() = dead

        override suspend fun close() {
            closeCount++
            dead = true
        }

        override suspend fun openOrThrow(
            hostname: String,
            port: Int,
            wait: Boolean,
            abort: Abort?,
        ): TorStreamDuplex {
            openCount++
            failOpen?.let { throw it }
            val (pub, priv) = pairedByteDuplexes()
            return TorStreamDuplex(pub) {
                try {
                    priv.close()
                } catch (_: Throwable) {
                }
            }
        }
    }

    private fun options(
        maxCircuitAgeMs: Long = 0,
        nowMs: () -> Long = { 0L },
        make: suspend (TorClientDuplex, Abort) -> Circuit,
    ) = ExitDialerOptions(maxCircuitAgeMs = maxCircuitAgeMs).apply {
        hooks =
            ExitDialerHooks(
                nowMs = nowMs,
                ensureTor = { TorClientDuplex() },
                makeCircuit = make,
            )
    }

    @Test
    fun reusesCircuitForSameHostPort() =
        runTest {
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options { _, _ -> RecordingCircuit(built.size + 1).also { built += it } },
                )
            try {
                val a = dialer.dial("Api.Example.com", 443)
                val b = dialer.dial("api.example.com", 443)
                a.close()
                b.close()
                assertEquals(1, built.size)
                assertEquals(2, built[0].openCount)
                assertEquals(0, built[0].closeCount)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun buildsAnotherCircuitForDifferentHostPort() =
        runTest {
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options { _, _ -> RecordingCircuit(built.size + 1).also { built += it } },
                )
            try {
                dialer.dial("a.example", 443).close()
                dialer.dial("b.example", 443).close()
                assertEquals(2, built.size)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun streamCloseDoesNotDestroyCachedCircuit() =
        runTest {
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options { _, _ -> RecordingCircuit(built.size + 1).also { built += it } },
                )
            try {
                dialer.dial("api.example", 443).close()
                dialer.dial("api.example", 443).close()
                dialer.dial("api.example", 443).close()
                assertEquals(1, built.size)
                assertEquals(3, built[0].openCount)
                assertEquals(0, built[0].closeCount)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun failedOpenKeepsTorAndRetriesCircuit() =
        runTest {
            val clients = ArrayList<TorClientDuplex>()
            val built = ArrayList<RecordingCircuit>()
            val opts =
                ExitDialerOptions().apply {
                    hooks =
                        ExitDialerHooks(
                            nowMs = { 0L },
                            ensureTor = { TorClientDuplex().also { clients += it } },
                            makeCircuit = { _, _ ->
                                RecordingCircuit(built.size + 1).also { circ ->
                                    if (built.isEmpty()) circ.failOpen = Exception("BEGIN failed")
                                    built += circ
                                }
                            },
                        )
                }
            val dialer = createExitDialer(opts)
            try {
                dialer.dial("api.example", 443).close()
                assertEquals(2, built.size)
                assertEquals(1, clients.size)
                assertTrue(clients[0].closed == null)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun failedOpenEvictsAndRetriesOnce() =
        runTest {
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options { _, _ ->
                        RecordingCircuit(built.size + 1).also { circ ->
                            if (built.isEmpty()) circ.failOpen = Exception("BEGIN failed")
                            built += circ
                        }
                    },
                )
            try {
                val stream = dialer.dial("api.example", 443)
                stream.close()
                assertEquals(2, built.size)
                assertEquals(1, built[0].closeCount)
                assertEquals(1, built[1].openCount)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun secondFailedOpenThrowsWithoutThirdBuild() =
        runTest {
            var builds = 0
            val dialer =
                createExitDialer(
                    options { _, _ ->
                        builds++
                        RecordingCircuit(builds).also { it.failOpen = Exception("BEGIN failed") }
                    },
                )
            try {
                val ex = assertFails { dialer.dial("api.example", 443) }
                assertTrue(ex.message?.contains("api.example") == true || ex.message?.contains("BEGIN") == true)
                assertEquals(2, builds)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun maxCircuitAgeEvictsStaleCircuit() =
        runTest {
            var now = 0L
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options(
                        maxCircuitAgeMs = 10_000,
                        nowMs = { now },
                    ) { _, _ -> RecordingCircuit(built.size + 1).also { built += it } },
                )
            try {
                dialer.dial("api.example", 443).close()
                now = 10_000
                dialer.dial("api.example", 443).close()
                assertEquals(2, built.size)
                assertEquals(1, built[0].closeCount)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun forgetCircuitForcesNewCircuit() =
        runTest {
            val built = ArrayList<RecordingCircuit>()
            val dialer =
                createExitDialer(
                    options { _, _ -> RecordingCircuit(built.size + 1).also { built += it } },
                )
            try {
                dialer.dial("api.example", 443).close()
                dialer.forgetCircuit("api.example", 443)
                dialer.dial("api.example", 443).close()
                assertEquals(2, built.size)
                assertEquals(1, built[0].closeCount)
            } finally {
                dialer.dispose()
            }
        }

    @Test
    fun reportsMonotonicProgressAndFinishesAt100() =
        runTest {
            val events = ArrayList<Pair<Int, String>>()
            val dialer =
                createExitDialer(
                    options { _, _ -> RecordingCircuit(1) },
                )
            try {
                val stream =
                    dialer.dial("example.com", 443) { percent, stage ->
                        events += percent to stage
                    }
                stream.close()
            } finally {
                dialer.dispose()
            }
            assertTrue(events.isNotEmpty(), "got $events")
            assertEquals(0, events.first().first)
            assertEquals("Starting", events.first().second)
            assertTrue(events.any { it.second == "Connecting" }, "got $events")
            assertTrue(events.any { it.second == "Opening connection" }, "got $events")
            assertEquals(100, events.last().first)
            assertEquals("Done", events.last().second)
            assertTrue(events.zipWithNext().all { it.first.first <= it.second.first }, "got $events")
        }
}
