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

    @Override
    public void onInitializeClient() {
        PayloadTypeRegistry.clientboundConfiguration().register(GuardPayload.CHALLENGE, GuardPayload.codec(GuardPayload.CHALLENGE));
        PayloadTypeRegistry.serverboundConfiguration().register(GuardPayload.HELLO, GuardPayload.codec(GuardPayload.HELLO));
        PayloadTypeRegistry.serverboundConfiguration().register(GuardPayload.RESPONSE, GuardPayload.codec(GuardPayload.RESPONSE));
        ClientConfigurationConnectionEvents.INIT.register((listener, client) -> {
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
                        report.addProperty("version", "1.0.1");
                        report.addProperty("ok", false);
                        try {
                            JsonObject challenge = JsonParser.parseString(new String(payload.bytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                            report.addProperty("nonce", challenge.get("nonce").getAsString());
                            if (challenge.get("protocol").getAsInt() != 1) throw new IllegalArgumentException("Protocol mismatch");
                            var loader = FabricLoader.getInstance();
                            var ids = loader.getAllMods().stream().map(mod -> mod.getMetadata().getId()).toList();
                            report = ModScanner.scan(loader.getGameDir().resolve("mods"), ids, challenge.getAsJsonObject("rules"), report);
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
            sender.sendPacket(new GuardPayload(GuardPayload.HELLO, "{\"protocol\":1,\"version\":\"1.0.1\"}".getBytes(StandardCharsets.UTF_8)));
            LOGGER.info("Guardian channel registered and readiness sent");
        });
    }
}
