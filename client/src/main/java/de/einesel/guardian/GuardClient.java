package de.einesel.guardian;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.fabric.api.client.networking.v1.ClientConfigurationNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;

public final class GuardClient implements ClientModInitializer {
    private static final java.util.concurrent.atomic.AtomicBoolean SCANNING = new java.util.concurrent.atomic.AtomicBoolean();
    private static final java.util.concurrent.ExecutorService SCANNER = Executors.newSingleThreadExecutor(task -> {
        Thread thread = new Thread(task, "guardian-mod-scan");
        thread.setDaemon(true);
        return thread;
    });

    @Override
    public void onInitializeClient() {
        PayloadTypeRegistry.clientboundConfiguration().register(GuardPayload.CHALLENGE, GuardPayload.codec(GuardPayload.CHALLENGE));
        PayloadTypeRegistry.serverboundConfiguration().register(GuardPayload.RESPONSE, GuardPayload.codec(GuardPayload.RESPONSE));
        ClientConfigurationNetworking.registerGlobalReceiver(GuardPayload.CHALLENGE, (payload, context) -> {
            if (!SCANNING.compareAndSet(false, true)) return;
            // Capture this connection's sender; never send a stale scan to a later connection.
            var sender = context.responseSender();
            SCANNER.execute(() -> {
                JsonObject report = new JsonObject();
                report.addProperty("protocol", 1);
                report.addProperty("version", "1.0.0");
                report.addProperty("ok", false);
                try {
                    JsonObject challenge = JsonParser.parseString(new String(payload.bytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                    report.addProperty("nonce", challenge.get("nonce").getAsString());
                    if (challenge.get("protocol").getAsInt() != 1) throw new IllegalArgumentException("Protocol mismatch");
                    var loader = FabricLoader.getInstance();
                    var ids = loader.getAllMods().stream().map(mod -> mod.getMetadata().getId()).toList();
                    report = ModScanner.scan(loader.getGameDir().resolve("mods"), ids, challenge.getAsJsonObject("rules"), report);
                } catch (Exception error) {
                    report.addProperty("ok", false);
                }
                byte[] bytes = report.toString().getBytes(StandardCharsets.UTF_8);
                if (bytes.length > GuardPayload.MAX_BYTES) {
                    report = new JsonObject();
                    report.addProperty("ok", false);
                    bytes = report.toString().getBytes(StandardCharsets.UTF_8);
                }
                try {
                    sender.sendPacket(new GuardPayload(GuardPayload.RESPONSE, bytes));
                } finally {
                    SCANNING.set(false);
                }
            });
        });
    }
}
