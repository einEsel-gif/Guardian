package de.einesel.guardian;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Exercises the production validator without a running Minecraft server. */
class ClientGuardReportTest {
    private static final String CLEAN = """
        {"protocol":1,"version":"1.0.1","nonce":"request-A","ok":true,
         "modIds":["fabricloader","guardian"],"findings":[]}
        """;

    private ClientGuardDecision evaluate(String json) {
        return ClientGuardReport.INSTANCE.evaluate(json.getBytes(StandardCharsets.UTF_8), "request-A", Set.of("meteor-client"));
    }

    @Test void allowsCleanReport() { assertEquals(ClientGuardDecision.ALLOW, evaluate(CLEAN)); }
    @Test void rejectsFailedScan() { assertEquals(ClientGuardDecision.SCAN_FAILED, evaluate(CLEAN.replace("\"ok\":true", "\"ok\":false"))); }
    @Test void blocksProhibitedId() { assertEquals(ClientGuardDecision.BLOCKED, evaluate(CLEAN.replace("fabricloader", "meteor-client"))); }
    @Test void blocksFindings() { assertEquals(ClientGuardDecision.BLOCKED, evaluate(CLEAN.replace("\"findings\":[]", "\"findings\":[\"class-rule:blocked/\"]"))); }
    @Test void rejectsReplayedNonce() { assertThrows(RuntimeException.class, () -> evaluate(CLEAN.replace("request-A", "request-B"))); }
    @Test void rejectsWrongVersion() { assertThrows(RuntimeException.class, () -> evaluate(CLEAN.replace("1.0.1", "0.9.0"))); }
    @Test void rejectsWrongProtocol() { assertThrows(RuntimeException.class, () -> evaluate(CLEAN.replace("\"protocol\":1", "\"protocol\":2"))); }
    @Test void requiresGuardianId() { assertThrows(RuntimeException.class, () -> evaluate(CLEAN.replace("guardian", "other-mod"))); }
    @Test void rejectsMissingFields() { assertThrows(RuntimeException.class, () -> evaluate("{}")); }
    @Test void rejectsMalformedJson() { assertThrows(RuntimeException.class, () -> evaluate("broken")); }
    @Test void rejectsOversizedPayload() { assertThrows(RuntimeException.class, () -> evaluate("x".repeat(30001))); }
}
