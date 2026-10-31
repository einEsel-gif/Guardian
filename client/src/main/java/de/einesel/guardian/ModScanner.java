package de.einesel.guardian;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/** Reads only the instance's mods directory. Never loads code from inspected archives. */
public final class ModScanner {
    private static final int MAX_NESTED_BYTES = 64 * 1024 * 1024;
    private static final long MAX_ARCHIVE_BYTES = 512L * 1024 * 1024;
    private final Set<String> findings = new TreeSet<>();
    private final Set<String> ids;
    private final List<String> tokens;
    private final List<String> prefixes;
    private final Set<String> hashes;
    private int entries;
    private long expanded;
    private final long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(25);

    private ModScanner(JsonObject rules) {
        ids = new TreeSet<>(strings(rules, "mod-ids"));
        tokens = strings(rules, "file-tokens");
        prefixes = strings(rules, "class-prefixes");
        hashes = new TreeSet<>(strings(rules, "sha256"));
    }

    private static List<String> strings(JsonObject rules, String key) {
        JsonArray values = rules.getAsJsonArray(key);
        if (values.size() > 512) throw new IllegalArgumentException("Too many rules");
        return values.asList().stream().map(value -> value.getAsString().toLowerCase(Locale.ROOT))
                .peek(value -> { if (value.isBlank() || value.length() > 256) throw new IllegalArgumentException("Invalid rule"); })
                .toList();
    }

    public static JsonObject scan(Path mods, List<String> loadedIds, JsonObject rules, JsonObject report) throws Exception {
        ModScanner scanner = new ModScanner(rules);
        if (loadedIds.isEmpty() || loadedIds.size() > 4096) throw new IOException("Invalid mod count");
        JsonArray modIds = new JsonArray();
        for (String id : loadedIds) {
            modIds.add(id);
            scanner.checkId(id);
        }
        if (!Files.isDirectory(mods)) throw new IOException("Missing mods directory");
        // Do not follow links out of the mods folder. Uninspectable entries fail closed.
        try (var paths = Files.walk(mods)) {
            var iterator = paths.iterator();
            int files = 0;
            while (iterator.hasNext()) {
                scanner.checkBudget();
                Path path = iterator.next();
                if (++files > 10000) throw new IOException("Too many files");
                if (Files.isSymbolicLink(path)) throw new IOException("Linked mods cannot be inspected");
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) continue;
                if (!path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".jar")) continue;
                if (Files.size(path) > MAX_ARCHIVE_BYTES) throw new IOException("Archive too large");
                scanner.checkName(path.getFileName().toString());
                if (!scanner.hashes.isEmpty()) {
                    try (InputStream input = Files.newInputStream(path)) { scanner.checkHash(input); }
                }
                try (ZipFile zip = new ZipFile(path.toFile())) {
                    var zipEntries = zip.entries();
                    while (zipEntries.hasMoreElements()) {
                        ZipEntry entry = zipEntries.nextElement();
                        scanner.checkEntry(entry.getName());
                        if (entry.isDirectory()) continue;
                        if (entry.getName().endsWith(".jar") || entry.getName().equals("fabric.mod.json")) {
                            try (InputStream input = zip.getInputStream(entry)) {
                                scanner.inspectContent(entry.getName(), input, 0);
                            }
                        }
                    }
                }
            }
        }
        JsonArray hits = new JsonArray();
        scanner.findings.forEach(hits::add);
        report.add("modIds", modIds);
        report.add("findings", hits);
        report.addProperty("ok", true);
        return report;
    }

    private void checkBudget() throws IOException {
        if (System.nanoTime() > deadline || expanded > 1024L * 1024 * 1024 || entries > 200000)
            throw new IOException("Scan limit exceeded");
    }

    private void hit(String value) throws IOException {
        findings.add(value);
        if (findings.size() > 128) throw new IOException("Too many findings");
    }

    private void checkId(String id) throws IOException {
        String lower = id.toLowerCase(Locale.ROOT);
        if (ids.contains(lower)) hit("mod:" + lower);
    }

    private void checkName(String name) throws IOException {
        String lower = name.toLowerCase(Locale.ROOT);
        for (String token : tokens) {
            if (Pattern.compile("(^|[^a-z0-9])" + Pattern.quote(token) + "(?=$|[^a-z])").matcher(lower).find())
                hit("filename-rule:" + token);
        }
    }

    private void checkEntry(String name) throws IOException {
        entries++;
        checkBudget();
        String normalized = name.replace('\\', '/').toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".class")) {
            for (String prefix : prefixes) if (normalized.startsWith(prefix)) hit("class-rule:" + prefix);
        }
    }

    private void checkHash(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[65536];
        long size = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            size += read;
            if (size > MAX_ARCHIVE_BYTES) throw new IOException("Archive too large");
            checkBudget();
            digest.update(buffer, 0, read);
        }
        String hash = HexFormat.of().formatHex(digest.digest());
        if (hashes.contains(hash)) hit("sha256:" + hash);
    }

    private void inspectContent(String name, InputStream input, int depth) throws Exception {
        boolean jar = name.toLowerCase(Locale.ROOT).endsWith(".jar");
        int limit = jar ? MAX_NESTED_BYTES : 1024 * 1024;
        byte[] bytes = input.readNBytes(limit + 1);
        expanded += bytes.length;
        checkBudget();
        if (bytes.length > limit) throw new IOException("Nested entry too large");
        if (!jar) {
            JsonObject metadata = JsonParser.parseString(new String(bytes, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
            checkId(metadata.get("id").getAsString());
            return;
        }
        if (depth >= 4) throw new IOException("Nested archive depth exceeded");
        if (bytes.length < 4 || bytes[0] != 'P' || bytes[1] != 'K') throw new IOException("Invalid nested archive");
        checkName(name.substring(name.lastIndexOf('/') + 1));
        if (!hashes.isEmpty()) checkHash(new ByteArrayInputStream(bytes));
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                checkEntry(entry.getName());
                if (entry.isDirectory()) continue;
                if (entry.getName().endsWith(".jar") || entry.getName().equals("fabric.mod.json")) {
                    inspectContent(entry.getName(), zip, depth + 1);
                } else {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = zip.read(buffer)) != -1) {
                        expanded += read;
                        checkBudget();
                    }
                }
            }
        }
    }
}
