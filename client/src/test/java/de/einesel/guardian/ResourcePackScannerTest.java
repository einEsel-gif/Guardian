package de.einesel.guardian;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipFile;
import static org.junit.jupiter.api.Assertions.*;

class ResourcePackScannerTest {
    private static final String CUBE = """
        {"elements":[{"from":[0,0,0],"to":[16,16,16],"faces":{
        "up":{"texture":"#all"},"down":{"texture":"#all"},
        "north":{"texture":"#all"},"south":{"texture":"#all"},
        "east":{"texture":"#all"},"west":{"texture":"#all"}}}]}
        """;
    private byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private byte[] png(int argb) throws Exception {
        BufferedImage image = new BufferedImage(2, 2, BufferedImage.TYPE_INT_ARGB);
        for (int x = 0; x < 2; x++) for (int y = 0; y < 2; y++) image.setRGB(x, y, argb);
        var stream = new ByteArrayOutputStream(); ImageIO.write(image, "png", stream); return stream.toByteArray();
    }
    private Map<String, byte[]> clean() throws Exception {
        Map<String, byte[]> files = new HashMap<>();
        for (String block : List.of("stone","deepslate","granite","diorite","andesite","tuff","netherrack","end_stone","dirt","gravel","sand","red_sand","clay")) {
            files.put("minecraft:blockstates/" + block + ".json", bytes("{\"variants\":{\"\":{\"model\":\"minecraft:block/stone\"}}}"));
        }
        files.put("minecraft:models/block/base.json", bytes(CUBE));
        files.put("minecraft:models/block/stone.json", bytes("{\"parent\":\"block/base\",\"textures\":{\"all\":\"minecraft:block/stone\"}}"));
        files.put("minecraft:textures/block/stone.png", png(0xff777777));
        return files;
    }
    @Test void allowsOpaqueVanillaStyleResources() throws Exception {
        assertTrue(ResourcePackScanner.scan(clean()::get).isEmpty());
    }
    @Test void allowsOrdinaryRetextures() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/stone.png", png(0xffff0000));
        assertTrue(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void detectsTransparentTerrainRegardlessOfPackName() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/stone.png", png(0x00777777));
        assertTrue(ResourcePackScanner.scan(files::get).toString().contains("xray:transparent-terrain:stone"));
    }
    @Test void detectsSemitransparentTerrain() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/stone.png", png(0x80777777));
        assertFalse(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void doesNotFlagOreOutlines() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/diamond_ore.png", png(0));
        assertTrue(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void detectsEmptyTerrainModel() throws Exception {
        var files = clean(); files.put("minecraft:models/block/base.json", bytes("{\"elements\":[]}"));
        assertTrue(ResourcePackScanner.scan(files::get).toString().contains("xray:hidden-terrain:stone"));
    }
    @Test void detectsBlockstateRemappedToEmptyCustomModel() throws Exception {
        var files = clean();
        files.put("minecraft:blockstates/stone.json", bytes("{\"variants\":{\"\":{\"model\":\"example:block/empty\"}}}"));
        files.put("example:models/block/empty.json", bytes("{\"elements\":[]}"));
        assertFalse(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void detectsTinyTerrainGeometry() throws Exception {
        var files = clean(); files.put("minecraft:models/block/base.json", bytes(CUBE.replace("[16,16,16]", "[1,1,1]")));
        assertFalse(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void inheritedTextureAliasesAreResolved() throws Exception {
        var files = clean();
        files.put("minecraft:models/block/stone.json", bytes("{\"parent\":\"block/base\",\"textures\":{\"all\":\"#surface\",\"surface\":\"minecraft:block/stone\"}}"));
        assertTrue(ResourcePackScanner.scan(files::get).isEmpty());
    }
    @Test void failsClosedOnModelCycles() throws Exception {
        var files = clean(); files.put("minecraft:models/block/base.json", bytes("{\"parent\":\"block/stone\"}"));
        assertThrows(Exception.class, () -> ResourcePackScanner.scan(files::get));
    }
    @Test void failsClosedOnTextureCycles() throws Exception {
        var files = clean(); files.put("minecraft:models/block/stone.json", bytes("{\"parent\":\"block/base\",\"textures\":{\"all\":\"#all\"}}"));
        assertThrows(Exception.class, () -> ResourcePackScanner.scan(files::get));
    }
    @Test void failsClosedOnMissingTerrainAssets() throws Exception {
        var files = clean(); files.remove("minecraft:textures/block/stone.png");
        assertThrows(Exception.class, () -> ResourcePackScanner.scan(files::get));
    }
    @Test void failsClosedOnInvalidImages() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/stone.png", bytes("not a PNG"));
        assertThrows(Exception.class, () -> ResourcePackScanner.scan(files::get));
    }
    @Test void usesTheEffectiveResourceAfterPackPriorityResolution() throws Exception {
        var files = clean(); files.put("minecraft:textures/block/stone.png", png(0));
        var override = Map.of("minecraft:textures/block/stone.png", png(0xffaabbcc));
        assertTrue(ResourcePackScanner.scan(id -> override.containsKey(id) ? override.get(id) : files.get(id)).isEmpty());
    }
    @Test @EnabledIfSystemProperty(named = "guardian.vanilla.jar", matches = ".+")
    void acceptsActualMinecraft263Resources() throws Exception {
        try (ZipFile zip = new ZipFile(System.getProperty("guardian.vanilla.jar"))) {
            assertTrue(ResourcePackScanner.scan(id -> {
                String[] parts = id.split(":", 2);
                var entry = zip.getEntry("assets/" + parts[0] + "/" + parts[1]);
                if (entry == null) return null;
                try (var input = zip.getInputStream(entry)) { return input.readNBytes(8 * 1024 * 1024 + 1); }
            }).isEmpty());
        }
    }
}
