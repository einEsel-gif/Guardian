package de.einesel.guardian;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.Yaml;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import static org.junit.jupiter.api.Assertions.*;

/** The two Freecam projects share classes; only their exact mod IDs distinguish them. */
class DefaultRulesTest {
    @TempDir Path mods;

    private JsonObject rules() throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/config.yml")) {
            assertNotNull(input);
            Map<String, Object> config = new Yaml().load(input);
            Map<?, ?> blocked = (Map<?, ?>) config.get("blocked");
            JsonObject rules = new JsonObject();
            for (String key : List.of("mod-ids", "file-tokens", "class-prefixes", "sha256")) {
                JsonArray values = new JsonArray();
                ((List<?>) blocked.get(key)).forEach(value -> values.add(value.toString()));
                rules.add(key, values);
            }
            return rules;
        }
    }

    private JsonArray scan(List<String> ids) throws Exception {
        return ModScanner.scan(mods, ids, rules(), new JsonObject()).getAsJsonArray("findings");
    }

    private void archive(String name, String id, String classPath) throws Exception {
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(mods.resolve(name)))) {
            zip.putNextEntry(new ZipEntry("fabric.mod.json"));
            zip.write(("{\"id\":\"" + id + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zip.closeEntry();
            if (classPath != null) {
                zip.putNextEntry(new ZipEntry(classPath));
                zip.closeEntry();
            }
        }
    }

    @Test void blocksOriginalFreecamId() throws Exception {
        assertTrue(scan(List.of("guardian", "freecam")).toString().contains("mod:freecam"));
    }
    @Test void blocksRenamedOriginalFreecam() throws Exception {
        archive("performance.jar", "freecam", "net/xolt/freecam/Freecam.class");
        assertTrue(scan(List.of("guardian")).toString().contains("mod:freecam"));
    }
    @Test void allowsLegacyFreecamWithSharedClasses() throws Exception {
        archive("legacyfreecam-fabric-2.0.0.jar", "legacyfreecam", "net/xolt/freecam/Freecam.class");
        assertTrue(scan(List.of("guardian", "legacyfreecam")).isEmpty());
    }
    @Test void allowsLegacyFreecamEvenWithOriginalFilename() throws Exception {
        archive("freecam-fabric.jar", "legacyfreecam", "net/xolt/freecam/Freecam.class");
        assertTrue(scan(List.of("guardian", "legacyfreecam")).isEmpty());
    }
    @Test void legacyDoesNotExemptOriginalFreecam() throws Exception {
        assertTrue(scan(List.of("guardian", "legacyfreecam", "freecam")).toString().contains("mod:freecam"));
    }
    @Test void legacyDoesNotExemptOtherCheatClasses() throws Exception {
        archive("legacyfreecam.jar", "legacyfreecam", "thunder/hack/ThunderHack.class");
        assertTrue(scan(List.of("guardian", "legacyfreecam")).toString().contains("class-rule:thunder/hack/"));
    }
    @Test void detectsRenamedThunderHack() throws Exception {
        archive("performance.jar", "unrelated", "thunder/hack/ThunderHack.class");
        assertFalse(scan(List.of("guardian")).isEmpty());
    }
    @Test void detectsRenamedMeteorRejects() throws Exception {
        archive("performance.jar", "unrelated", "anticope/rejects/MeteorRejectsAddon.class");
        assertFalse(scan(List.of("guardian")).isEmpty());
    }
    @Test void blocksNewCheatIds() throws Exception {
        for (String id : List.of("thunderhack", "meteor-rejects")) {
            assertTrue(scan(List.of("guardian", id)).toString().contains("mod:" + id));
        }
    }

    // Optional local checks read official downloads without executing their code.
    @Test @EnabledIfSystemProperty(named = "guardian.fixture.dir", matches = ".+")
    void blocksOfficialFreecamDownload() throws Exception {
        Files.copy(Path.of(System.getProperty("guardian.fixture.dir"), "freecam.jar"), mods.resolve("renamed.jar"));
        assertTrue(scan(List.of("guardian")).toString().contains("mod:freecam"));
    }
    @Test @EnabledIfSystemProperty(named = "guardian.fixture.dir", matches = ".+")
    void allowsOfficialLegacyFreecamDownload() throws Exception {
        Files.copy(Path.of(System.getProperty("guardian.fixture.dir"), "legacyfreecam.jar"), mods.resolve("renamed.jar"));
        assertTrue(scan(List.of("guardian", "legacyfreecam")).isEmpty());
    }
}
