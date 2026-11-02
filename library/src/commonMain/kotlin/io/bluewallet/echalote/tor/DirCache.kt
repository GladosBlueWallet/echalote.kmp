package io.bluewallet.echalote

import kotlinx.coroutines.CancellationException
import kotlin.concurrent.Volatile

/**
 * Persistent storage for public Tor directory documents (the microdesc consensus and the
 * directory authorities' key certificates), so a cold start can skip downloading them.
 *
 * Everything stored here is public, and nothing read back is trusted: a cached consensus is
 * re-parsed and its signatures are verified against re-verified authority certificates exactly
 * like a fresh download, and anything that fails is deleted.
 *
 * Implementations should make [write] atomic (write a temp file, then rename it over the old
 * one), so a crash never leaves a partial document. Any method may throw; echalote logs the
 * error and carries on as if the cache were empty, so a broken cache never breaks Tor.
 *
 * The default is [None], which stores nothing. Install one with [Echalote.dirCache].
 */
interface TorDirCache {
    /** Returns the bytes last written under [key], or null if there are none. */
    suspend fun read(key: String): ByteArray?

    /** Stores [bytes] under [key], replacing any previous value. */
    suspend fun write(
        key: String,
        bytes: ByteArray,
    )

    /** Removes [key]. Removing a missing key is not an error. */
    suspend fun delete(key: String)

    companion object {
        /** Key of the raw `consensus-microdesc` document, exactly as downloaded. */
        const val CONSENSUS_MICRODESC: String = "consensus-microdesc"

        /** Key of the concatenated raw `dir-key-certificate-version 3` documents. */
        const val AUTHORITY_CERTS: String = "authority-certs"

        /** Stores nothing; the default. */
        val None: TorDirCache =
            object : TorDirCache {
                override suspend fun read(key: String): ByteArray? = null

                override suspend fun write(
                    key: String,
                    bytes: ByteArray,
                ) = Unit

                override suspend fun delete(key: String) = Unit

                override fun toString(): String = "TorDirCache.None"
            }
    }
}

/** Process-wide directory cache; see [Echalote.dirCache]. */
@Volatile
internal var torDirCache: TorDirCache = TorDirCache.None

/**
 * How long past its valid-until a cached consensus is still used (while a fresh one downloads
 * in the background). dir-spec calls a consensus "reasonably live" for 24 hours after
 * valid-until; C tor uses the same window.
 */
internal const val CONSENSUS_REASONABLY_LIVE_MS = 24 * 60 * 60 * 1000L

@Suppress("TooGenericExceptionCaught") // A cache problem must never break Tor.
internal suspend fun TorDirCache.readOrNull(key: String): ByteArray? =
    try {
        read(key)
    } catch (err: CancellationException) {
        throw err
    } catch (err: Exception) {
        println("echalote.dircache read failed key=$key ${err.message ?: err}")
        null
    }

@Suppress("TooGenericExceptionCaught") // A cache problem must never break Tor.
internal suspend fun TorDirCache.writeOrLog(
    key: String,
    bytes: ByteArray,
) {
    try {
        val started = timeMark()
        write(key, bytes)
        logTiming("dircache", "write", started.elapsedNow(), "key=$key bytes=${bytes.size}")
    } catch (err: CancellationException) {
        throw err
    } catch (err: Exception) {
        println("echalote.dircache write failed key=$key ${err.message ?: err}")
    }
}

@Suppress("TooGenericExceptionCaught") // A cache problem must never break Tor.
internal suspend fun TorDirCache.deleteOrLog(key: String) {
    try {
        delete(key)
        println("echalote.dircache deleted key=$key")
    } catch (err: CancellationException) {
        throw err
    } catch (err: Exception) {
        println("echalote.dircache delete failed key=$key ${err.message ?: err}")
    }
}
