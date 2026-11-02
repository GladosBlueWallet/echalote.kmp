package io.bluewallet.echalote

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

private class SocketDuplex(
    private val socket: Socket,
) : ByteDuplex {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()
    private val writeLock = Mutex()

    override suspend fun read(n: Int): ByteArray =
        withContext(Dispatchers.IO) {
            val buf = ByteArray(n)
            val got =
                try {
                    input.read(buf)
                } catch (_: java.io.IOException) {
                    -1
                }
            if (got <= 0) ByteArray(0) else buf.copyOf(got)
        }

    override suspend fun write(bytes: ByteArray) {
        writeLock.withLock {
            withContext(Dispatchers.IO) {
                output.write(bytes)
                output.flush()
            }
        }
    }

    override fun close() {
        try {
            socket.close()
        } catch (_: Throwable) {
        }
    }
}

internal actual suspend fun platformTcpConnect(
    host: String,
    port: Int,
    timeoutMs: Long,
): ByteDuplex? =
    withContext(Dispatchers.IO) {
        val socket = Socket()
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(host, port), timeoutMs.toInt().coerceAtLeast(1))
            SocketDuplex(socket)
        } catch (e: Throwable) {
            socket.close()
            throw e
        }
    }
