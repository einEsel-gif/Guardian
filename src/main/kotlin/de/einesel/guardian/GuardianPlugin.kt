package de.einesel.guardian

import org.bukkit.plugin.java.JavaPlugin

class GuardianPlugin : JavaPlugin() {
    private var guard: ClientGuard? = null

    override fun onEnable() {
        guard = ClientGuard(this).also { it.register() }
    }

    override fun onDisable() {
        guard?.close()
        guard = null
    }
}
