package de.einesel.guardian

import com.destroystokyo.paper.event.player.PlayerConnectionCloseEvent
import com.google.gson.JsonObject
import io.papermc.paper.connection.PlayerConfigurationConnection
import io.papermc.paper.connection.PlayerConnection
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent
import io.papermc.paper.event.connection.configuration.PlayerConnectionInitialConfigureEvent
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

/** Client reports are an admission policy, not trusted proof of client integrity. */
class ClientGuard(private val plugin: JavaPlugin) : Listener, PluginMessageListener {
    private data class Pending(val playerId: UUID?, val nonce: String = UUID.randomUUID().toString(), val handshake: GuardHandshake = GuardHandshake())
    private val pending = ConcurrentHashMap<PlayerConnection, Pending>()
    private lateinit var rules: JsonObject
    private var enabled = true
    private var timeoutSeconds = 30L
    private var helloTimeoutSeconds = 5L

    fun register() {
        val file = File(plugin.dataFolder, "config.yml")
        if (!file.exists()) plugin.saveResource("config.yml", false)
        val config = YamlConfiguration.loadConfiguration(file)
        enabled = config.getBoolean("enabled", true)
        timeoutSeconds = config.getLong("timeout-seconds", 30).coerceIn(5, 120)
        helloTimeoutSeconds = config.getLong("handshake-timeout-seconds", 5).coerceIn(2, 15)
        rules = JsonObject().apply {
            for (key in listOf("mod-ids", "file-tokens", "class-prefixes", "sha256")) {
                add(key, com.google.gson.JsonArray().also { array ->
                    config.getStringList("blocked.$key").forEach { array.add(it.lowercase(java.util.Locale.ROOT)) }
                })
            }
        }
        plugin.server.messenger.registerOutgoingPluginChannel(plugin, CHALLENGE)
        plugin.server.messenger.registerIncomingPluginChannel(plugin, HELLO, this)
        plugin.server.messenger.registerIncomingPluginChannel(plugin, RESPONSE, this)
        plugin.server.pluginManager.registerEvents(this, plugin)
    }

    @EventHandler
    fun onInitialConfigure(event: PlayerConnectionInitialConfigureEvent) {
        if (!enabled) return
        // The client can send HELLO before the later async configuration event runs.
        pending.putIfAbsent(event.connection, Pending(event.connection.profile.id))
    }

    @EventHandler
    fun onConfigure(event: AsyncPlayerConnectionConfigureEvent) {
        if (!enabled) return
        val connection = event.connection
        val request = pending.computeIfAbsent(connection) { Pending(connection.profile.id) }
        try {
            val challenge = JsonObject().apply {
                addProperty("protocol", 1)
                addProperty("nonce", request.nonce)
                add("rules", rules)
            }.toString().toByteArray(Charsets.UTF_8)
            val bytes = request.handshake.awaitReport(helloTimeoutSeconds * 1000, timeoutSeconds * 1000, Runnable {
                // Bukkit's channel set belongs to the server thread. Registration precedes HELLO.
                val sent = CompletableFuture<Unit>()
                plugin.server.scheduler.runTask(plugin, Runnable {
                    try {
                        check(connection.isConnected && CHALLENGE in connection.listeningPluginChannels) {
                            "Client did not register the Guardian challenge channel"
                        }
                        connection.sendPluginMessage(plugin, CHALLENGE, challenge)
                        sent.complete(Unit)
                    } catch (error: Exception) { sent.completeExceptionally(error) }
                })
                sent.get(helloTimeoutSeconds, TimeUnit.SECONDS)
            })
            val blockedIds = rules["mod-ids"].asJsonArray.map { it.asString }.toSet()
            when (ClientGuardReport.evaluate(bytes, request.nonce, blockedIds)) {
                ClientGuardDecision.ALLOW -> Unit
                ClientGuardDecision.SCAN_FAILED -> reject(connection, "Mod verification failed. Check your client log and mods folder, then reconnect.")
                ClientGuardDecision.BLOCKED -> reject(connection, "A blocked mod was detected. Remove prohibited mods and restart Minecraft.")
            }
        } catch (_: java.util.concurrent.TimeoutException) {
            if (!request.handshake.isReady) {
                reject(connection, "This server requires Guardian 1.0.1 and Fabric API for Minecraft 26.3. No Guardian handshake was received.")
            } else {
                plugin.logger.warning("Guardian scan timed out for ${request.playerId} after ${timeoutSeconds}s")
                reject(connection, "Guardian connected, but the mod scan timed out. Check your client log and reconnect.")
            }
        } catch (error: Exception) {
            if (connection.isConnected) plugin.logger.warning("Guardian handshake failed for ${request.playerId}: ${error.cause?.message ?: error.message}")
            reject(connection, "Guardian verification failed. Update both the server plugin and client mod to 1.0.1.")
        } finally { pending.remove(connection, request) }
    }

    private fun reject(connection: PlayerConfigurationConnection, reason: String) {
        if (connection.isConnected) connection.disconnect(Component.text(reason))
    }

    @EventHandler
    fun onConnectionClose(event: PlayerConnectionCloseEvent) {
        pending.entries.removeIf { (connection, request) ->
            if (request.playerId != event.playerUniqueId || connection.isConnected) false
            else { request.handshake.close(); true }
        }
    }

    override fun onPluginMessageReceived(channel: String, player: Player, message: ByteArray) = Unit

    override fun onPluginMessageReceived(channel: String, connection: PlayerConnection, message: ByteArray) {
        val request = pending[connection] ?: return
        when (channel) {
            HELLO -> request.handshake.receiveHello(message)
            RESPONSE -> request.handshake.receiveReport(message)
        }
    }

    fun close() {
        pending.values.forEach { it.handshake.close() }
        pending.clear()
        plugin.server.messenger.unregisterIncomingPluginChannel(plugin, HELLO, this)
        plugin.server.messenger.unregisterIncomingPluginChannel(plugin, RESPONSE, this)
        plugin.server.messenger.unregisterOutgoingPluginChannel(plugin, CHALLENGE)
    }

    companion object {
        const val HELLO = "guardian:hello"
        const val CHALLENGE = "guardian:challenge"
        const val RESPONSE = "guardian:response"
    }
}
