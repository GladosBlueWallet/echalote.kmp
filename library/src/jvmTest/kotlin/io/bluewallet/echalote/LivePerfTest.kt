package io.bluewallet.echalote

import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One timed live run, for performance work. Skipped unless ECHALOTE_LIVE_PERF=1.
 *  ECHALOTE_PERF_CACHE_DIR  directory for a file-backed TorDirCache (unset: no disk cache)
 *  ECHALOTE_PERF_URL        URL to fetch (default: RocketX configs, ~173 KB of JSON)
 *  ECHALOTE_PERF_DIRECT=1   direct guard connection instead of meek
 *  ECHALOTE_PERF_WARMUP=1   warm up the HTTPS session first and time it separately
 * Fetches the URL over a real Tor circuit twice (first, then warm on the same dialer) with
 * verbose tracing on, and checks each response is a 200 with a JSON body.
 */
class LivePerfTest {
    private class FileCache(
        private val dir: File,
    ) : TorDirCache {
        override suspend fun read(key: String): ByteArray? = File(dir, key).takeIf { it.isFile }?.readBytes()

        override suspend fun write(
            key: String,
            bytes: ByteArray,
        ) {
            dir.mkdirs()
            val tmp = File(dir, "$key.tmp")
            tmp.writeBytes(bytes)
            tmp.renameTo(File(dir, key))
        }

        override suspend fun delete(key: String) {
            File(dir, key).delete()
        }
    }

    @Test
    fun live_perf_run() {
        if (System.getenv("ECHALOTE_LIVE_PERF") != "1") return
        System.getenv("ECHALOTE_PERF_CACHE_DIR")?.let { Echalote.dirCache = FileCache(File(it)) }
        val url = System.getenv("ECHALOTE_PERF_URL") ?: "https://api.rocketx.exchange/v1/configs"
        Echalote.verboseTrace = true
        Echalote.directRelay = System.getenv("ECHALOTE_PERF_DIRECT") == "1"
        resetTlsSessionCache()
        runBlocking {
            if (System.getenv("ECHALOTE_PERF_WARMUP") == "1") {
                Echalote.traceMark("warmup-start")
                val started = System.nanoTime()
                Echalote.warmUp(url)
                println("PERF warmup ms=${(System.nanoTime() - started) / 1_000_000}")
            }
            for (label in listOf("first", "warm")) {
                Echalote.traceMark("$label-start")
                val started = System.nanoTime()
                val res = Echalote.fetch(url, Abort())
                val ms = (System.nanoTime() - started) / 1_000_000
                Echalote.traceMark("$label-done ms=$ms status=${res.status} bytes=${res.body.size}")
                println("PERF $label ms=$ms status=${res.status} bytes=${res.body.size}")
                assertEquals(200, res.status)
                assertTrue(res.body.isNotEmpty() && res.body[0] == '{'.code.toByte(), "not JSON")
            }
            awaitDirRefresh()
        }
    }
}
