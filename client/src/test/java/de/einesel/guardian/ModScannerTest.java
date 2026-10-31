package de.einesel.guardian;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.jupiter.api.Assertions.*;

class ModScannerTest {
    @TempDir Path mods;
    private JsonObject rules() {
        return JsonParser.parseString("""
            {"mod-ids":["meteor-client","wurst"],"file-tokens":["wurst"],
             "class-prefixes":["meteordevelopment/meteorclient/"],"sha256":[]}
            """).getAsJsonObject();
    }
    private JsonObject scan() throws Exception {
        return ModScanner.scan(mods, List.of("fabricloader", "guardian"), rules(), new JsonObject());
    }
    private static byte[] jar(Map<String, byte[]> entries) throws Exception {
        var output = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(output)) {
            for (var entry : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(entry.getKey()));
                zip.write(entry.getValue());
                zip.closeEntry();
            }
        }
        return output.toByteArray();
    }
    @Test void allowsCleanModsAndDoesNotInspectOtherFiles() throws Exception {
        Files.write(mods.resolve("sodium.jar"), jar(Map.of("fabric.mod.json", "{\"id\":\"sodium\"}".getBytes())));
        Files.writeString(mods.resolve("private.txt"), "not an archive");
        assertTrue(scan().get("ok").getAsBoolean());
        assertTrue(scan().getAsJsonArray("findings").isEmpty());
    }
    @Test void detectsLoadedId() throws Exception {
        var report = ModScanner.scan(mods, List.of("meteor-client"), rules(), new JsonObject());
        assertTrue(report.getAsJsonArray("findings").toString().contains("mod:meteor-client"));
    }
    @Test void detectsRenamedJarByClass() throws Exception {
        Files.write(mods.resolve("performance.jar"), jar(Map.of("meteordevelopment/meteorclient/Test.class", new byte[0])));
        assertTrue(scan().getAsJsonArray("findings").toString().contains("class-rule:"));
    }
    @Test void detectsNestedMetadata() throws Exception {
        byte[] nested = jar(Map.of("fabric.mod.json", "{\"id\":\"wurst\"}".getBytes()));
        Files.write(mods.resolve("innocent.jar"), jar(Map.of("META-INF/jars/other.jar", nested)));
        assertTrue(scan().getAsJsonArray("findings").toString().contains("mod:wurst"));
    }
    @Test void detectsVersionedFilenameButAvoidsSubstring() throws Exception {
        byte[] empty = jar(Map.of());
        Files.write(mods.resolve("Wurst7.0.jar"), empty);
        assertFalse(scan().getAsJsonArray("findings").isEmpty());
        Files.delete(mods.resolve("Wurst7.0.jar"));
        Files.write(mods.resolve("bratwurst-helper.jar"), empty);
        assertTrue(scan().getAsJsonArray("findings").isEmpty());
    }
    @Test void detectsConfiguredHash() throws Exception {
        byte[] bytes = jar(Map.of());
        Files.write(mods.resolve("renamed.jar"), bytes);
        var config = rules();
        String hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
        config.getAsJsonArray("sha256").add(hash);
        assertTrue(ModScanner.scan(mods, List.of("fabricloader"), config, new JsonObject())
                .getAsJsonArray("findings").toString().contains(hash));
    }
    @Test void failsOnCorruptArchive() throws Exception {
        Files.writeString(mods.resolve("broken.jar"), "broken");
        assertThrows(Exception.class, this::scan);
    }
    @Test void failsOnInvalidMetadata() throws Exception {
        Files.write(mods.resolve("broken.jar"), jar(Map.of("fabric.mod.json", "broken".getBytes())));
        assertThrows(Exception.class, this::scan);
    }
    @Test void failsOnCorruptNestedJar() throws Exception {
        Files.write(mods.resolve("outer.jar"), jar(Map.of("broken.jar", "broken".getBytes())));
        assertThrows(Exception.class, this::scan);
    }
    @Test void failsOnExcessiveNesting() throws Exception {
        byte[] bytes = jar(Map.of());
        for (int i = 0; i < 6; i++) bytes = jar(Map.of("nested.jar", bytes));
        Files.write(mods.resolve("deep.jar"), bytes);
        assertThrows(Exception.class, this::scan);
    }
}
