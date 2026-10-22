package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * fetchFirstOk must abort every loser, including one launched (after another worker failed)
 * at the moment the race ends. A loser stuck in non-suspending work (like a signature check)
 * only stops through its Abort, not through coroutine cancellation. Real threads, many rounds.
 */
class FetchFirstOkStopWorkersTest {
    private class Round {
        val spinning = AtomicInteger(0)
        val timedOut = AtomicInteger(0)
        val races = ConcurrentLinkedQueue<Abort>()

        /** Busy work that only ends when [race] aborts (or after 3 s, which counts as a leak). */
        fun spinUntilAborted(race: Abort) {
            spinning.incrementAndGet()
            val deadline = System.nanoTime() + 3_000_000_000L
            try {
                while (!race.aborted) {
                    if (System.nanoTime() > deadline) {
                        timedOut.incrementAndGet()
                        return
                    }
                }
            } finally {
                spinning.decrementAndGet()
            }
            race.throwIfAborted()
        }

        suspend fun awaitSettled() = withTimeout(10_000) { while (spinning.get() > 0) delay(1) }
    }

    @Test
    fun everyLoserIsAbortedWhenAWorkerWins() =
        runBlocking(Dispatchers.Default) {
            repeat(ROUNDS) { round ->
                val r = Round()
                val winner = (round % 5) + 3
                val result =
                    fetchFirstOk(
                        (0 until 16).toList(),
                        worker = { i, race ->
                            r.races += race
                            when {
                                i == winner -> i
                                i % 2 == 0 -> error("fail fast $i") // keeps launching replacements
                                else -> {
                                    r.spinUntilAborted(race)
                                    -1
                                }
                            }
                        },
                        concurrency = 4,
                    )
                assertEquals(winner, result)
                r.awaitSettled()
                assertEquals(0, r.timedOut.get(), "round $round: a loser never saw its abort")
            }
        }

    @Test
    fun everyWorkerIsAbortedWhenTheCallerIsCancelled() =
        runBlocking(Dispatchers.Default) {
            repeat(ROUNDS) { round ->
                val r = Round()
                val call =
                    async {
                        fetchFirstOk(
                            (0 until 16).toList(),
                            worker = { i, race ->
                                r.races += race
                                if (i % 2 == 0) error("fail fast $i")
                                r.spinUntilAborted(race)
                                -1
                            },
                            concurrency = 4,
                        )
                    }
                while (r.races.isEmpty()) delay(1)
                call.cancelAndJoin()
                r.awaitSettled()
                assertEquals(0, r.timedOut.get(), "round $round: a worker never saw its abort")
            }
        }

    private companion object {
        const val ROUNDS = 200
    }
}
