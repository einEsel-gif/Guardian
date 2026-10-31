package de.einesel.guardian;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import javax.imageio.ImageIO;
import javax.imageio.stream.MemoryCacheImageInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Checks effective resources: Minecraft has already resolved ZIPs, folders and pack priority. */
public final class ResourcePackScanner {
    @FunctionalInterface
    public interface Resources { byte[] read(String identifier) throws IOException; }

    private static final List<String> BLOCKS = List.of("stone", "deepslate", "granite", "diorite", "andesite",
            "tuff", "netherrack", "end_stone", "dirt", "gravel", "sand", "red_sand", "clay");
    private record Model(JsonArray elements, Map<String, String> textures) {}
    private final Resources resources;
    private final Map<String, Model> models = new HashMap<>();
    private final Map<String, Boolean> transparent = new HashMap<>();
    private final Set<String> findings = new TreeSet<>();
    private final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    private long bytesRead;

    private ResourcePackScanner(Resources resources) { this.resources = resources; }

    public static JsonArray scan(Resources resources) throws IOException {
        ResourcePackScanner scanner = new ResourcePackScanner(resources);
        for (String block : BLOCKS) scanner.inspectBlock(block);
        JsonArray findings = new JsonArray();
        scanner.findings.forEach(findings::add);
        return findings;
    }

    private void budget() throws IOException {
        if (System.nanoTime() > deadline || bytesRead > 64L * 1024 * 1024 || Thread.currentThread().isInterrupted())
            throw new IOException("Resource scan limit exceeded");
    }

    private byte[] read(String id, int limit) throws IOException {
        budget();
        if (!id.matches("[a-z0-9_.-]+:[a-z0-9_./-]+") || Arrays.asList(id.split("[:/]" )).contains(".."))
            throw new IOException("Invalid resource identifier");
        byte[] bytes = resources.read(id);
        if (bytes == null || bytes.length > limit) throw new IOException("Missing or oversized resource: " + id);
        bytesRead += bytes.length;
        budget();
        return bytes;
    }

    private JsonObject json(String id) throws IOException {
        try { return JsonParser.parseString(new String(read(id, 1024 * 1024), StandardCharsets.UTF_8)).getAsJsonObject(); }
        catch (RuntimeException error) { throw new IOException("Invalid resource JSON: " + id, error); }
    }

    private static String asset(String reference, String folder, String suffix) throws IOException {
        if (reference.startsWith("#")) throw new IOException("Unresolved model reference");
        String[] parts = reference.contains(":") ? reference.split(":", 2) : new String[]{"minecraft", reference};
        return parts[0] + ":" + folder + parts[1] + suffix;
    }

    private void inspectBlock(String block) throws IOException {
        Set<String> references = new HashSet<>();
        collectModels(json("minecraft:blockstates/" + block + ".json"), references, 0);
        if (references.isEmpty()) { findings.add("xray:missing-model:" + block); return; }
        for (String reference : references) inspectModel(block, model(reference, new HashSet<>()));
    }

    private void collectModels(JsonElement element, Set<String> references, int depth) throws IOException {
        if (depth > 32 || references.size() > 128) throw new IOException("Blockstate limit exceeded");
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            if (object.has("model")) references.add(object.get("model").getAsString());
            for (var entry : object.entrySet()) if (entry.getValue().isJsonObject() || entry.getValue().isJsonArray())
                collectModels(entry.getValue(), references, depth + 1);
        } else if (element.isJsonArray()) {
            for (JsonElement child : element.getAsJsonArray()) collectModels(child, references, depth + 1);
        }
    }

    private Model model(String reference, Set<String> chain) throws IOException {
        String id = asset(reference, "models/", ".json");
        if (models.containsKey(id)) return models.get(id);
        if (!chain.add(id) || chain.size() > 16 || models.size() > 256) throw new IOException("Model inheritance limit exceeded");
        try {
            JsonObject object = json(id);
            Model parent = object.has("parent") ? model(object.get("parent").getAsString(), chain) : new Model(new JsonArray(), Map.of());
            Map<String, String> textures = new HashMap<>(parent.textures());
            if (object.has("textures")) object.getAsJsonObject("textures").entrySet().forEach(entry -> textures.put(entry.getKey(), entry.getValue().getAsString()));
            Model resolved = new Model(object.has("elements") ? object.getAsJsonArray("elements") : parent.elements(), textures);
            models.put(id, resolved);
            return resolved;
        } catch (RuntimeException error) { throw new IOException("Invalid model: " + id, error); }
        finally { chain.remove(id); }
    }

    private void inspectModel(String block, Model model) throws IOException {
        if (model.elements().size() > 4096) throw new IOException("Too many model elements");
        double volume = 0, area = 0;
        Set<String> usedTextures = new HashSet<>();
        try {
            for (JsonElement value : model.elements()) {
                JsonObject element = value.getAsJsonObject();
                JsonArray from = element.getAsJsonArray("from"), to = element.getAsJsonArray("to");
                double x = to.get(0).getAsDouble() - from.get(0).getAsDouble();
                double y = to.get(1).getAsDouble() - from.get(1).getAsDouble();
                double z = to.get(2).getAsDouble() - from.get(2).getAsDouble();
                if (!Double.isFinite(x + y + z) || x < 0 || y < 0 || z < 0) throw new IOException("Invalid model geometry");
                volume += x * y * z;
                if (!element.has("faces")) continue;
                for (var face : element.getAsJsonObject("faces").entrySet()) {
                    area += switch (face.getKey()) {
                        case "down", "up" -> x * z;
                        case "north", "south" -> x * y;
                        case "west", "east" -> y * z;
                        default -> 0;
                    };
                    usedTextures.add(texture(face.getValue().getAsJsonObject().get("texture").getAsString(), model.textures()));
                }
            }
        } catch (RuntimeException error) { throw new IOException("Invalid block geometry: " + block, error); }
        // Only inspect normally solid terrain. Ore outlines, foliage and glass are not targeted.
        if (volume < 512 || area <= 256) findings.add("xray:hidden-terrain:" + block);
        for (String texture : usedTextures) if (isTransparent(texture)) findings.add("xray:transparent-terrain:" + block);
    }

    private String texture(String reference, Map<String, String> textures) throws IOException {
        Set<String> chain = new HashSet<>();
        while (reference.startsWith("#")) {
            if (!chain.add(reference) || chain.size() > 32) throw new IOException("Texture reference cycle");
            reference = textures.get(reference.substring(1));
            if (reference == null) throw new IOException("Missing model texture");
        }
        return asset(reference, "textures/", ".png");
    }

    private boolean isTransparent(String id) throws IOException {
        if (transparent.containsKey(id)) return transparent.get(id);
        byte[] bytes = read(id, 8 * 1024 * 1024);
        try (var stream = new MemoryCacheImageInputStream(new ByteArrayInputStream(bytes))) {
            var readers = ImageIO.getImageReaders(stream);
            if (!readers.hasNext()) throw new IOException("Unsupported terrain texture");
            var reader = readers.next();
            try {
                reader.setInput(stream);
                int width = reader.getWidth(0), height = reader.getHeight(0);
                if (width < 1 || height < 1 || (long) width * height > 4L * 1024 * 1024) throw new IOException("Terrain texture too large");
                var image = reader.read(0);
                long clear = 0, pixels = (long) width * height;
                for (int y = 0; y < height; y++) {
                    budget();
                    for (int x = 0; x < width; x++) if ((image.getRGB(x, y) >>> 24) < 250) clear++;
                }
                boolean result = clear * 2 >= pixels;
                transparent.put(id, result);
                return result;
            } finally { reader.dispose(); }
        }
    }
}
