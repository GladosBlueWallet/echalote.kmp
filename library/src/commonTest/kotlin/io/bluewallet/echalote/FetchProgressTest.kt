package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FetchProgressTest {
    @Test
    fun reportsStageLabelsAndPercentsWithoutGoingBackwards() {
        val events = ArrayList<Pair<Int, String>>()
        val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }

        reporter.report(FetchStage.STARTING)
        reporter.report(FetchStage.CONNECTING)
        reporter.report(FetchStage.CONNECTING, 1.0)
        reporter.report(FetchStage.DOWNLOADING_DIRECTORY)
        reporter.report(FetchStage.STARTING)

        assertEquals(0, events[0].first)
        assertEquals("Starting", events[0].second)
        assertEquals("Connecting", events[1].second)
        assertEquals(15, events[2].first)
        assertEquals("Downloading directory", events[3].second)
        assertTrue(events.zipWithNext().all { it.first.first <= it.second.first })
        assertEquals(false, events.any { it.second == "Starting" && it.first > 0 && events.indexOf(it) > 0 })
    }

    @Test
    fun interpolatesDownloadBytesInsideAStageRange() {
        val events = ArrayList<Pair<Int, String>>()
        val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }

        reporter.report(FetchStage.DOWNLOADING_DIRECTORY)
        reporter.downloadBytes(0, 100)
        reporter.downloadBytes(50, 100)
        reporter.downloadBytes(100, 100)

        val directory = events.filter { it.second == "Downloading directory" }
        assertEquals(15, directory.first().first)
        assertEquals(30, directory[directory.size - 2].first)
        assertEquals(44, directory.last().first)
        reporter.report(FetchStage.DOWNLOADING_DIRECTORY, 1.0)
        assertEquals(45, events.last().first)
        assertTrue(events.zipWithNext().all { it.first.first <= it.second.first })
    }

    @Test
    fun aFinishedSmallDownloadDoesNotCompleteTheStage() {
        val events = ArrayList<Pair<Int, String>>()
        val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }
        reporter.report(FetchStage.DOWNLOADING_DIRECTORY)
        reporter.downloadBytes(200, 200)
        assertTrue(events.last().first < 45, "got $events")
        reporter.report(FetchStage.DOWNLOADING_DIRECTORY, 1.0)
        assertEquals(45, events.last().first)
    }

    @Test
    fun ignoredEarlierStageDoesNotStealDownloadTicks() {
        val events = ArrayList<Pair<Int, String>>()
        val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }
        reporter.report(FetchStage.BUILDING_CIRCUIT, 0.5)
        reporter.report(FetchStage.FETCHING_RELAY_INFO)
        reporter.downloadBytes(80, 100)
        assertEquals("Building circuit", events.last().second)
        assertEquals(75, events.last().first)
    }

    @Test
    fun lateTicksFromAnEarlierStageDoNotAdvanceALaterStage() {
        val events = ArrayList<Pair<Int, String>>()
        val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }
        reporter.report(FetchStage.DOWNLOADING_DIRECTORY)
        reporter.report(FetchStage.BUILDING_CIRCUIT)
        reporter.downloadBytes(FetchStage.DOWNLOADING_DIRECTORY, 90, 100)
        assertEquals("Building circuit", events.last().second)
        assertEquals(55, events.last().first)
    }

    @Test
    fun listenerReentryDoesNotHang() {
        lateinit var reporter: FetchProgressReporter
        var calls = 0
        reporter =
            FetchProgressReporter { _, _ ->
                calls++
                reporter.report(FetchStage.DONE)
            }
        reporter.report(FetchStage.STARTING)
        reporter.report(FetchStage.CONNECTING, 1.0)
        assertEquals(2, calls)
    }

    @Test
    fun concurrentTicksNeverGoBackwards() =
        runTest {
            val events = Channel<Int>(Channel.UNLIMITED)
            val reporter = FetchProgressReporter { percent, _ -> events.trySend(percent) }
            reporter.report(FetchStage.DOWNLOADING_DIRECTORY)
            withContext(Dispatchers.Default) {
                repeat(32) { i ->
                    launch {
                        reporter.downloadBytes(i + 1, 32)
                    }
                }
            }
            val snapshot =
                buildList {
                    while (true) {
                        add(events.tryReceive().getOrNull() ?: break)
                    }
                }
            assertTrue(snapshot.zipWithNext().all { it.first <= it.second }, "got $snapshot")
        }

    @Test
    fun listenerExceptionsDoNotEscape() {
        val reporter =
            FetchProgressReporter { _, _ ->
                throw IllegalStateException("ui exploded")
            }
        reporter.report(FetchStage.STARTING)
        reporter.report(FetchStage.DONE)
    }

    @Test
    fun fetchMicrodescConsensusReportsDirectoryDownload() =
        runTest {
            val text =
                """
                network-status-version 3 microdesc
                vote-status consensus
                consensus-method 35
                valid-after 2026-08-07 07:00:00
                fresh-until 2026-08-07 08:00:00
                valid-until 2026-08-07 10:00:00
                voting-delay 300 300
                known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc V2Dir Valid
                r c0der AjUfyI0L8G9s3lRSZWZB5hGdvX4 2038-01-01 00:00:00 95.216.20.80 8080 0
                m mkHw/LD1moosjemRD+GqSqXzzK1kOvK3ZwTsCPGJIFs
                s Fast Guard Running Stable V2Dir Valid
                v Tor 0.4.8.8
                pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4
                w Bandwidth=34000
                directory-footer
                """.trimIndent()
            val events = ArrayList<Pair<Int, String>>()
            val reporter = FetchProgressReporter { percent, stage -> events += percent to stage }
            val engine =
                HttpEngine { _, _, _, _, _, _ ->
                    HttpResponse(200, text.encodeToByteArray())
                }
            try {
                withContext(FetchProgressContext(reporter)) {
                    fetchMicrodescConsensus(
                        force = true,
                        mirrors = listOf("http://127.0.0.1/consensus"),
                        engine = engine,
                    )
                }
            } finally {
                resetCachedConsensus()
            }
            val directory = events.filter { it.second == "Downloading directory" }
            assertTrue(directory.isNotEmpty(), "got $events")
            assertEquals(15, directory.first().first)
            assertEquals(45, directory.last().first)
        }
}
