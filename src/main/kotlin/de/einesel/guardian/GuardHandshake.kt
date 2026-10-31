package de.einesel.guardian

import com.google.gson.JsonParser
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Keeps early readiness packets and prevents reports from preceding their challenge. */
class GuardHandshake {
    private val ready = CompletableFuture<Unit>()
    private val report = CompletableFuture<ByteArray>()
    private val challengeSent = AtomicBoolean()
    val isReady: Boolean get() = ready.isDone && !ready.isCompletedExceptionally

    fun receiveHello(bytes: ByteArray) {
        try {
            require(bytes.size in 1..512)
            val hello = JsonParser.parseString(bytes.toString(Charsets.UTF_8)).asJsonObject
            require(hello["protocol"].asInt == 1 && hello["version"].asString == "1.0.2")
            ready.complete(Unit)
        } catch (error: Exception) {
            ready.completeExceptionally(error)
        }
    }

    fun receiveReport(bytes: ByteArray) {
        if (!challengeSent.get()) return
        if (bytes.size !in 1..30000) report.completeExceptionally(IllegalArgumentException("Report too large"))
        else report.complete(bytes.copyOf())
    }

    fun awaitReport(helloTimeoutMillis: Long, reportTimeoutMillis: Long, sendChallenge: Runnable): ByteArray {
        ready.get(helloTimeoutMillis, TimeUnit.MILLISECONDS)
        challengeSent.set(true)
        sendChallenge.run()
        return report.get(reportTimeoutMillis, TimeUnit.MILLISECONDS)
    }

    fun close() {
        val error = IllegalStateException("Connection closed")
        ready.completeExceptionally(error)
        report.completeExceptionally(error)
    }
}
