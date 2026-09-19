package io.bluewallet.echalote

import kotlinx.coroutines.sync.Mutex
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext

fun interface FetchProgressListener {
    fun onProgress(
        percent: Int,
        stage: String,
    )
}

internal enum class FetchStage(
    val label: String,
    val startPercent: Int,
    val endPercent: Int,
) {
    STARTING("Starting", 0, 0),
    CONNECTING("Connecting", 0, 15),
    DOWNLOADING_DIRECTORY("Downloading directory", 15, 45),
    FETCHING_RELAY_INFO("Fetching relay info", 45, 55),
    BUILDING_CIRCUIT("Building circuit", 55, 80),
    OPENING_CONNECTION("Opening connection", 80, 90),
    SENDING_REQUEST("Sending request", 90, 95),
    DOWNLOADING_RESPONSE("Downloading response", 95, 100),
    DONE("Done", 100, 100),
}

internal class FetchProgressContext(
    val reporter: FetchProgressReporter,
) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<FetchProgressContext>
}

internal suspend fun fetchProgress(): FetchProgressReporter? = coroutineContext[FetchProgressContext.Key]?.reporter

internal suspend fun http1ProgressSink(): ((Int, Int?) -> Unit)? {
    val progress = fetchProgress()
    val stage = progress?.activeStage()
    if (progress == null || stage == null) return null
    return { received, total -> progress.downloadBytes(stage, received, total) }
}

internal class FetchProgressReporter(
    private val listener: FetchProgressListener?,
) {
    private val mutex = Mutex()
    private var lastPercent = -1
    private var lastStage: String? = null
    private var downloadStage: FetchStage? = null

    fun activeStage(): FetchStage? = downloadStage

    fun report(
        stage: FetchStage,
        fraction: Double = 0.0,
    ) {
        if (listener == null) return
        val span = stage.endPercent - stage.startPercent
        val raw = stage.startPercent + (span * fraction.coerceIn(0.0, 1.0)).toInt()
        emit(raw, stage.label, stage)
    }

    fun downloadBytes(
        received: Int,
        total: Int?,
    ) {
        val stage = downloadStage ?: return
        downloadBytes(stage, received, total)
    }

    fun downloadBytes(
        stage: FetchStage,
        received: Int,
        total: Int?,
    ) {
        val fraction =
            if (total != null && total > 0) {
                received.toDouble() / total.toDouble()
            } else {
                0.0
            }
        val span = stage.endPercent - stage.startPercent
        val progressed = stage.startPercent + (span * fraction.coerceIn(0.0, 1.0)).toInt()
        val raw = if (span > 0) minOf(progressed, stage.endPercent - 1) else progressed
        emit(raw, stage.label, null)
    }

    private fun emit(
        rawPercent: Int,
        stage: String,
        download: FetchStage?,
    ) {
        if (listener == null || !mutex.tryLock()) return
        try {
            val raw = rawPercent.coerceIn(0, 100)
            if (raw < lastPercent || (raw == lastPercent && stage == lastStage)) return
            lastPercent = raw
            lastStage = stage
            if (download != null) downloadStage = download
            try {
                listener.onProgress(raw, stage)
            } catch (_: Throwable) {
            }
        } finally {
            mutex.unlock()
        }
    }
}
