package org.hazae41.echalote

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSData
import platform.Foundation.NSHTTPURLResponse
import platform.Foundation.NSMutableURLRequest
import platform.Foundation.NSURL
import platform.Foundation.NSURLSession
import platform.Foundation.NSURLSessionConfiguration
import platform.Foundation.create
import platform.Foundation.dataTaskWithRequest
import platform.Foundation.setHTTPBody
import platform.Foundation.setHTTPMethod
import platform.Foundation.setValue
import platform.posix.memcpy
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@OptIn(ExperimentalForeignApi::class)
private fun NSData.toByteArray(): ByteArray {
    val size = length.toInt()
    if (size == 0) return ByteArray(0)
    val out = ByteArray(size)
    out.usePinned { pinned ->
        memcpy(pinned.addressOf(0), bytes, size.convert())
    }
    return out
}

@OptIn(ExperimentalForeignApi::class)
actual fun defaultHttpEngine(): HttpEngine {
    val session = NSURLSession.sessionWithConfiguration(NSURLSessionConfiguration.ephemeralSessionConfiguration)
    return HttpEngine { method, url, headers, body, timeoutMs, _ ->
        suspendCancellableCoroutine { cont ->
            val nsUrl = NSURL.URLWithString(url) ?: run {
                cont.resumeWithException(IllegalArgumentException("bad url $url"))
                return@suspendCancellableCoroutine
            }
            val req = NSMutableURLRequest.requestWithURL(nsUrl)
            req.setHTTPMethod(method)
            req.setTimeoutInterval(timeoutMs / 1000.0)
            for ((k, v) in headers) req.setValue(v, forHTTPHeaderField = k)
            if (body.isNotEmpty()) {
                body.usePinned { pinned ->
                    req.setHTTPBody(NSData.create(bytes = pinned.addressOf(0), length = body.size.convert()))
                }
            }
            val task = session.dataTaskWithRequest(req) { data, response, error ->
                if (error != null) {
                    cont.resumeWithException(Exception(error.localizedDescription))
                    return@dataTaskWithRequest
                }
                val http = response as? NSHTTPURLResponse
                val status = http?.statusCode?.toInt() ?: 0
                val bytes = data?.toByteArray() ?: ByteArray(0)
                val hdrs = mutableMapOf<String, String>()
                val dict = http?.allHeaderFields
                if (dict != null) {
                    for ((k, v) in dict) {
                        hdrs[k.toString()] = v.toString()
                    }
                }
                cont.resume(HttpResponse(status, bytes, hdrs))
            }
            cont.invokeOnCancellation { task.cancel() }
            task.resume()
        }
    }
}
