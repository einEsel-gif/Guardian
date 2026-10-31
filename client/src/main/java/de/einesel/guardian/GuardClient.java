package de.einesel.guardian;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.impl.networking.RegistrationPayload;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.resource.v1.ResourceLoader;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientPacketListener;
import net.minecraft.resources.Identifier;
import net.minecraft.server.packs.PackType;
import net.minecraft.server.packs.resources.ResourceManager;
import net.minecraft.server.packs.resources.ResourceManagerReloadListener;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class GuardClient implements ClientModInitializer {
    private static final Logger LOGGER = LoggerFactory.getLogger("Guardian");
    private static final java.util.concurrent.ExecutorService SCANNER = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "guardian-mod-scan");
        thread.setDaemon(true);
        return thread;
    });

    private static final class Session {
        final Object configurationListener;
        final AtomicBoolean resourceScanning = new AtomicBoolean();
        final AtomicBoolean resourceDirty = new AtomicBoolean();
        volatile ClientPacketListener playListener;
        volatile JsonObject baseline;
        Session(Object listener) { configurationListener = listener; }
    }
    private static volatile Session session;

    private static ResourcePackScanner.Resources resources(ResourceManager manager) {
        return id -> {
            var resource = manager.getResource(Identifier.parse(id));
            if (resource.isEmpty()) return null;
            try (var input = resource.get().open()) { return input.readNBytes(8 * 1024 * 1024 + 1); }
        };
    }

    private static void checkResourcePacks(Minecraft client) {
        Session current = session;
        if (current == null || current.playListener == null || current.baseline == null) return;
        current.resourceDirty.set(true);
        if (!current.resourceScanning.compareAndSet(false, true)) return;
        SCANNER.execute(() -> {
            try {
                do {
                    current.resourceDirty.set(false);
                    JsonObject update = current.baseline.deepCopy();
                    try {
                        update.add("findings", ResourcePackScanner.scan(resources(client.getResourceManager())));
                        update.addProperty("resourcePacksChecked", true);
                    } catch (Exception error) {
                        LOGGER.warn("Guardian resource pack check failed", error);
                        update.addProperty("ok", false);
                    }
                    JsonObject result = update;
                    // Never send a completed scan to a newer connection or a different server.
                    client.execute(() -> {
                        if (session == current && client.getConnection() == current.playListener && !current.resourceDirty.get()) {
                            ClientPlayNetworking.send(new GuardPayload(GuardPayload.RESPONSE, result.toString().getBytes(StandardCharsets.UTF_8)));
                        }
                    });
                } while (current.resourceDirty.get() && session == current);
            } finally {
                current.resourceScanning.set(false);
                // A reload may have arrived between the final dirty check and clearing the flag.
                if (current.resourceDirty.get() && session == current) client.execute(() -> checkResourcePacks(client));
            }
        });
    }

    @Override
    public void onInitializeClient() {
        PayloadTypeRegistry.clientboundConfiguration().register(GuardPayload.CHALLENGE, GuardPayload.codec(GuardPayload.CHALLENGE));
        PayloadTypeRegistry.serverboundConfiguration().register(GuardPayload.HELLO, GuardPayload.codec(GuardPayload.HELLO));
        PayloadTypeRegistry.serverboundConfiguration().register(GuardPayload.RESPONSE, GuardPayload.codec(GuardPayload.RESPONSE));
        PayloadTypeRegistry.serverboundPlay().register(GuardPayload.RESPONSE, GuardPayload.codec(GuardPayload.RESPONSE));
        ResourceLoader.get(PackType.CLIENT_RESOURCES).registerReloadListener(Identifier.fromNamespaceAndPath("guardian", "xray"),
                (ResourceManagerReloadListener) manager -> checkResourcePacks(Minecraft.getInstance()));
        ClientPlayConnectionEvents.JOIN.register((listener, sender, client) -> {
            Session current = session;
            if (current != null) { current.playListener = listener; checkResourcePacks(client); }
        });
        ClientPlayConnectionEvents.DISCONNECT.register((listener, client) -> {
            Session current = session;
            if (current != null && current.playListener == listener) session = null;
        });
        ClientConfigurationConnectionEvents.DISCONNECT.register((listener, client) -> {
            Session current = session;
            if (current != null && current.configurationListener == listener) session = null;
        });
        ClientConfigurationConnectionEvents.INIT.register((listener, client) -> {
            Session current = new Session(listener);
            session = current;
            // Readiness and scan state belong to this connection, not the previous server.
            AtomicBoolean scanning = new AtomicBoolean();
            ClientConfigurationNetworking.registerReceiver(GuardPayload.CHALLENGE, (payload, context) -> {
                if (!scanning.compareAndSet(false, true)) return;
                var sender = context.responseSender();
                LOGGER.info("Guardian challenge received; starting mod scan");
                SCANNER.execute(() -> {
                    try {
                        JsonObject report = new JsonObject();
                        report.addProperty("protocol", 1);
                        report.addProperty("version", "1.0.2");
                        report.addProperty("ok", false);
                        try {
                            JsonObject challenge = JsonParser.parseString(new String(payload.bytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                            report.addProperty("nonce", challenge.get("nonce").getAsString());
                            if (challenge.get("protocol").getAsInt() != 1) throw new IllegalArgumentException("Protocol mismatch");
                            var loader = FabricLoader.getInstance();
                            var ids = loader.getAllMods().stream().map(mod -> mod.getMetadata().getId()).toList();
                            report = ModScanner.scan(loader.getGameDir().resolve("mods"), ids, challenge.getAsJsonObject("rules"), report);
                            var findings = report.getAsJsonArray("findings");
                            ResourcePackScanner.scan(resources(context.client().getResourceManager())).forEach(findings::add);
                            report.addProperty("resourcePacksChecked", true);
                        } catch (Exception error) {
                            LOGGER.warn("Guardian mod scan failed", error);
                            report.addProperty("ok", false);
                        }
                        byte[] bytes = report.toString().getBytes(StandardCharsets.UTF_8);
                        if (bytes.length > GuardPayload.MAX_BYTES) {
                            report.remove("modIds");
                            report.remove("findings");
                            report.addProperty("ok", false);
                            bytes = report.toString().getBytes(StandardCharsets.UTF_8);
                        }
                        if (session == current) current.baseline = report.deepCopy();
                        sender.sendPacket(new GuardPayload(GuardPayload.RESPONSE, bytes));
                        LOGGER.info("Guardian scan report sent");
                    } catch (Exception error) {
                        LOGGER.warn("Could not send Guardian scan report", error);
                    } finally { scanning.set(false); }
                });
            });
        });
        ClientConfigurationConnectionEvents.START.register((listener, client) -> {
            var sender = ClientConfigurationNetworking.getSender();
            // Fabric normally advertises channels in response to a Fabric server. Paper
            // needs the vanilla registration explicitly; otherwise it drops the challenge.
            // Reuse Fabric's registered codec rather than replacing minecraft:register.
            sender.sendPacket(new RegistrationPayload(RegistrationPayload.REGISTER, List.of(GuardPayload.CHALLENGE.id())));
            sender.sendPacket(new GuardPayload(GuardPayload.HELLO, "{\"protocol\":1,\"version\":\"1.0.2\"}".getBytes(StandardCharsets.UTF_8)));
            LOGGER.info("Guardian channel registered and readiness sent");
        });
    }
}
