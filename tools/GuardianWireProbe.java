import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/** Offline localhost-only protocol probe; never used by the production plugin. */
public class GuardianWireProbe implements AutoCloseable {
    final Socket socket;
    final InputStream input;
    final OutputStream output;
    int compression = -1;

    GuardianWireProbe() throws Exception {
        socket = new Socket("127.0.0.1", 25579);
        socket.setSoTimeout(12000);
        input = socket.getInputStream(); output = socket.getOutputStream();
    }
    static int varInt(InputStream in) throws IOException {
        int value = 0;
        for (int shift = 0; shift < 35; shift += 7) {
            int b = in.read(); if (b < 0) throw new EOFException();
            value |= (b & 127) << shift;
            if ((b & 128) == 0) return value;
        }
        throw new IOException("Invalid VarInt");
    }
    static void varInt(OutputStream out, int value) throws IOException {
        do { int b = value & 127; value >>>= 7; out.write(value == 0 ? b : b | 128); } while (value != 0);
    }
    static void string(OutputStream out, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8); varInt(out, bytes.length); out.write(bytes);
    }
    static String string(InputStream in) throws IOException { return new String(in.readNBytes(varInt(in)), StandardCharsets.UTF_8); }
    void send(int id, byte[] payload) throws Exception {
        var packet = new ByteArrayOutputStream(); varInt(packet, id); packet.write(payload);
        byte[] bytes = packet.toByteArray();
        if (compression >= 0) {
            var framed = new ByteArrayOutputStream();
            if (bytes.length >= compression) {
                varInt(framed, bytes.length);
                Deflater deflater = new Deflater();
                try {
                    deflater.setInput(bytes); deflater.finish(); byte[] buffer = new byte[8192];
                    while (!deflater.finished()) framed.write(buffer, 0, deflater.deflate(buffer));
                } finally { deflater.end(); }
            } else { varInt(framed, 0); framed.write(bytes); }
            bytes = framed.toByteArray();
        }
        varInt(output, bytes.length); output.write(bytes); output.flush();
    }
    ByteArrayInputStream receive() throws Exception {
        int size = varInt(input); if (size < 0 || size > 16 * 1024 * 1024) throw new IOException("Packet too large");
        var packet = new ByteArrayInputStream(input.readNBytes(size));
        if (compression < 0) return packet;
        int expanded = varInt(packet);
        if (expanded == 0) return packet;
        if (expanded > 32 * 1024 * 1024) throw new IOException("Expanded packet too large");
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(packet.readAllBytes()); byte[] bytes = new byte[expanded]; int offset = 0;
            while (!inflater.finished() && offset < bytes.length) { int n = inflater.inflate(bytes, offset, bytes.length - offset); if (n == 0) break; offset += n; }
            if (offset != expanded) throw new IOException("Incomplete compressed packet");
            return new ByteArrayInputStream(bytes);
        } finally { inflater.end(); }
    }
    void payload(String channel, String text) throws Exception {
        var packet = new ByteArrayOutputStream(); string(packet, channel); packet.write(text.getBytes(StandardCharsets.UTF_8)); send(2, packet.toByteArray());
    }
    void playPayload(String channel, String text) throws Exception {
        var packet = new ByteArrayOutputStream(); string(packet, channel); packet.write(text.getBytes(StandardCharsets.UTF_8)); send(22, packet.toByteArray());
    }
    void ready(String mode) throws Exception {
        payload("minecraft:register", "guardian:challenge");
        if (!mode.equals("register-only")) payload("guardian:hello", "{\"protocol\":1,\"version\":\"" + (mode.equals("old") ? "1.0.0" : "1.0.2") + "\"}");
    }
    void login(String name) throws Exception {
        var packet = new ByteArrayOutputStream(); varInt(packet, 777); string(packet, "localhost"); new DataOutputStream(packet).writeShort(25579); varInt(packet, 2); send(0, packet.toByteArray());
        packet.reset(); string(packet, name); UUID id = UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(StandardCharsets.UTF_8));
        var data = new DataOutputStream(packet); data.writeLong(id.getMostSignificantBits()); data.writeLong(id.getLeastSignificantBits()); send(0, packet.toByteArray());
        while (true) {
            var response = receive(); int idPacket = varInt(response);
            if (idPacket == 3) compression = varInt(response);
            else if (idPacket == 2) { send(3, new byte[0]); return; }
            else if (idPacket == 0) throw new AssertionError("Login rejected: " + new String(response.readAllBytes(), StandardCharsets.UTF_8));
            else throw new AssertionError("Unexpected login packet: " + idPacket);
        }
    }
    static void check(String mode, boolean allowed) throws Exception {
        long started = System.nanoTime(); boolean challenge = false; JsonObject lastReport = null;
        try (var client = new GuardianWireProbe()) {
            client.login("Probe" + mode.replace("-", "").substring(0, Math.min(10, mode.replace("-", "").length())));
            while (true) {
                var packet = client.receive(); int id = varInt(packet);
                if (id == 1) {
                    String channel = string(packet);
                    if (channel.equals("minecraft:brand") && !mode.equals("missing") && !mode.equals("late")) client.ready(mode);
                    if (channel.equals("guardian:challenge")) {
                        challenge = true;
                        if (mode.equals("missing") || mode.equals("register-only")) throw new AssertionError("Challenge sent before HELLO");
                        var request = JsonParser.parseString(new String(packet.readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                        var report = new JsonObject(); report.addProperty("protocol", 1); report.addProperty("version", "1.0.2"); report.addProperty("nonce", request.get("nonce").getAsString()); report.addProperty("ok", true); report.addProperty("resourcePacksChecked", !mode.equals("unchecked"));
                        JsonArray ids = new JsonArray(); ids.add("guardian"); if (mode.equals("blocked")) ids.add("freecam"); if (mode.equals("legacy")) ids.add("legacyfreecam"); report.add("modIds", ids); JsonArray findings = new JsonArray(); if (mode.equals("xray")) findings.add("xray:transparent-terrain:stone"); report.add("findings", findings);
                        lastReport = report;
                        client.payload("guardian:response", report.toString());
                    }
                } else if (id == 15) {
                    client.send(7, new byte[]{0});
                    if (mode.equals("late")) { Thread.sleep(300); client.ready(mode); }
                } else if (id == 4) client.send(4, packet.readAllBytes());
                else if (id == 5) client.send(5, packet.readAllBytes());
                else if (id == 3) {
                    if (mode.equals("reload-xray")) {
                        if (!challenge || lastReport == null) throw new AssertionError("No initial check");
                        client.send(3, new byte[0]);
                        boolean updateSent = false;
                        while (true) {
                            var gamePacket = client.receive(); int gameId = varInt(gamePacket);
                            if (!updateSent) {
                                lastReport.getAsJsonArray("findings").add("xray:transparent-terrain:stone");
                                client.playPayload("guardian:response", lastReport.toString()); updateSent = true;
                            }
                            if (gameId == 32) {
                                String reason = new String(gamePacket.readAllBytes(), StandardCharsets.UTF_8);
                                if (!reason.contains("Xray resource pack")) throw new AssertionError(reason);
                                System.out.println("PASS reload-xray: server kicked an admitted player after an Xray update"); return;
                            }
                        }
                    }
                    if (!allowed || !challenge) throw new AssertionError("Unexpected world admission: " + mode);
                    System.out.printf("PASS %s: admission after valid challenge/report (%.2fs)%n", mode, (System.nanoTime() - started) / 1e9); return;
                } else if (id == 2) {
                    String reason = new String(packet.readAllBytes(), StandardCharsets.UTF_8);
                    if (allowed) throw new AssertionError("Unexpected disconnect: " + mode + " " + reason);
                    if (mode.equals("blocked") && !reason.contains("blocked mod")) throw new AssertionError(reason);
                    if (mode.equals("xray") && !reason.contains("Xray resource pack")) throw new AssertionError(reason);
                    if (mode.equals("unchecked") && !reason.contains("Update both")) throw new AssertionError(reason);
                    if ((mode.equals("missing") || mode.equals("register-only")) && !reason.contains("No Guardian handshake")) throw new AssertionError(reason);
                    if (mode.equals("old") && !reason.contains("Update both")) throw new AssertionError(reason);
                    System.out.printf("PASS %s: correctly rejected (%.2fs)%n", mode, (System.nanoTime() - started) / 1e9); return;
                }
            }
        }
    }
    public void close() throws IOException { socket.close(); }
    public static void main(String[] args) throws Exception {
        check("clean", true); check("late", true); check("legacy", true); check("blocked", false); check("xray", false); check("unchecked", false); check("reload-xray", false); check("old", false); check("missing", false); check("register-only", false);
    }
}
