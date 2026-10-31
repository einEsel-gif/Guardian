package de.einesel.guardian

import com.google.gson.JsonParser
import java.util.Locale

enum class ClientGuardDecision { ALLOW, SCAN_FAILED, BLOCKED }

/** Pure report validation; malformed reports throw and must never grant access. */
object ClientGuardReport {
    fun evaluate(bytes: ByteArray, nonce: String, blockedIds: Set<String>): ClientGuardDecision {
        require(bytes.size in 1..30000)
        val report = JsonParser.parseString(bytes.toString(Charsets.UTF_8)).asJsonObject
        require(report["protocol"].asInt == 1 && report["nonce"].asString == nonce)
        require(report["version"].asString == "1.0.2")
        if (!report["ok"].asBoolean) return ClientGuardDecision.SCAN_FAILED
        require(report.has("resourcePacksChecked") && report["resourcePacksChecked"].asBoolean)
        val ids = report["modIds"].asJsonArray
        require(ids.size() in 1..4096)
        val loadedIds = ids.map { it.asString.also { id -> require(id.length in 1..128) } }
        require("guardian" in loadedIds)
        val hits = report["findings"].asJsonArray
        require(hits.size() <= 128)
        return if (loadedIds.any { it.lowercase(Locale.ROOT) in blockedIds } || !hits.isEmpty) {
            ClientGuardDecision.BLOCKED
        } else ClientGuardDecision.ALLOW
    }
}
