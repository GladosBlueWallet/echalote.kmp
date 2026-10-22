package io.bluewallet.echalote

import kotlin.time.Duration
import kotlin.time.TimeSource

/*
 * Cheap, greppable timing lines on the monotonic clock:
 *   echalote.<area>.timing stage=<name> ms=<elapsed> thread=<thread> [key=value ...]
 * Used to see where a cold start spends its time. One line per stage, never per relay.
 */

internal typealias TimeMark = TimeSource.Monotonic.ValueTimeMark

internal fun timeMark(): TimeMark = TimeSource.Monotonic.markNow()

internal fun Duration.msText(): String {
    val us = inWholeMicroseconds
    return "${us / 1000}.${(us % 1000) / 100}"
}

internal fun logTiming(
    area: String,
    stage: String,
    elapsed: Duration,
    extra: String = "",
) {
    val tail = if (extra.isEmpty()) "" else " $extra"
    println("echalote.$area.timing stage=$stage ms=${elapsed.msText()} thread=${currentThreadName()}$tail")
}

internal inline fun <T> timed(
    area: String,
    stage: String,
    extra: () -> String = { "" },
    block: () -> T,
): T {
    val start = timeMark()
    try {
        return block()
    } finally {
        logTiming(area, stage, start.elapsedNow(), extra())
    }
}

internal expect fun currentThreadName(): String
