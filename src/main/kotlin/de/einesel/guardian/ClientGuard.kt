package de.einesel.guardian

import com.google.gson.JsonObject
import io.papermc.paper.connection.PlayerConfigurationConnection
import io.papermc.paper.connection.PlayerConnection
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent
import net.kyori.adventure.text.Component
import org.bukkit.configuration.file.YamlConfiguration
import org.bukkit.entity.Player
import org.bukkit.event.EventHandler
import org.bukkit.event.Listener
import org.bukkit.plugin.java.JavaPlugin
import org.bukkit.plugin.messaging.PluginMessageListener
import java.io.File
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** The client report is an admission policy, not trusted proof of client integrity. */
class ClientGuard(private val plugin: JavaPlugin) : Listener, PluginMessageListener {
    private data class Pending(val nonce: String, val reply: CompletableFuture<ByteArray>)
    private val pending = ConcurrentHashMap<PlayerConnection, Pending>()
    private lateinit var rules: JsonObject
    private var enabled = true
    private var timeoutSeconds = 30L

    fun register() {
        val file = File(plugin.dataFolder, "config.yml")
        if (!file.exists()) plugin.saveResource("config.yml", false)
        val config = YamlConfiguration.loadConfiguration(file)
        enabled = config.getBoolean("enabled", true)
        timeoutSeconds = config.getLong("timeout-seconds", 30).coerceIn(5, 120)
        rules = JsonObject().apply {
            for (key in listOf("mod-ids", "file-tokens", "class-prefixes", "sha256")) {
                add(key, com.google.gson.JsonArray().also { array ->
                    config.getStringList("blocked.$key").forEach { array.add(it.lowercase(java.util.Locale.ROOT)) }
                })
            }
        }
        plugin.server.messenger.registerOutgoingPluginChannel(plugin, CHALLENGE)
        plugin.server.messenger.registerIncomingPluginChannel(plugin, RESPONSE, this)
        plugin.server.pluginManager.registerEvents(this, plugin)
    }

    @EventHandler
    fun onConfigure(event: AsyncPlayerConnectionConfigureEvent) {
        if (!enabled) return
        val connection = event.connection
        // Bind the challenge to the connection, not just the player's account.
        val request = Pending(UUID.randomUUID().toString(), CompletableFuture())
        pending[connection] = request
        try {
            val challenge = JsonObject().apply {
                addProperty("protocol", 1)
                addProperty("nonce", request.nonce)
                add("rules", rules)
            }
            connection.sendPluginMessage(plugin, CHALLENGE, challenge.toString().toByteArray(Charsets.UTF_8))
            // Paper holds configuration until this async event returns; no world entry yet.
            val bytes = request.reply.get(timeoutSeconds, TimeUnit.SECONDS)
            val blockedIds = rules["mod-ids"].asJsonArray.map { it.asString }.toSet()
            when (ClientGuardReport.evaluate(bytes, request.nonce, blockedIds)) {
                ClientGuardDecision.ALLOW -> Unit
                ClientGuardDecision.SCAN_FAILED -> reject(connection,
                    "Mod verification failed. Please check your mods folder and reconnect.")
                ClientGuardDecision.BLOCKED -> reject(connection,
                    "A blocked mod was detected. Remove prohibited mods from your mods folder and restart Minecraft.")
            }
        } catch (_: java.util.concurrent.TimeoutException) {
            reject(connection, "This server requires Guardian 1.0.0 and Fabric API for Minecraft 26.3. Guardian is missing or did not respond in time.")
        } catch (_: Exception) {
            reject(connection, "Invalid mod verification. Please reinstall Guardian 1.0.0.")
        } finally {
            pending.remove(connection, request)
        }
    }

    private fun reject(connection: PlayerConfigurationConnection, reason: String) {
        connection.disconnect(Component.text(reason))
    }

    override fun onPluginMessageReceived(channel: String, player: Player, message: ByteArray) = Unit

    override fun onPluginMessageReceived(channel: String, connection: PlayerConnection, message: ByteArray) {
        if (channel != RESPONSE) return
        val request = pending[connection] ?: return
        // Bound the report before copying or parsing client-controlled data.
        if (message.size !in 1..MAX_BYTES) {
            request.reply.completeExceptionally(IllegalArgumentException("Report too large"))
        } else {
            request.reply.complete(message.copyOf())
        }
    }

    fun close() {
        pending.values.forEach { it.reply.completeExceptionally(IllegalStateException("Plugin stopped")) }
        pending.clear()
        plugin.server.messenger.unregisterIncomingPluginChannel(plugin, RESPONSE, this)
        plugin.server.messenger.unregisterOutgoingPluginChannel(plugin, CHALLENGE)
    }

    companion object {
        const val CHALLENGE = "guardian:challenge"
        const val RESPONSE = "guardian:response"
        const val MAX_BYTES = 30000
    }
}
