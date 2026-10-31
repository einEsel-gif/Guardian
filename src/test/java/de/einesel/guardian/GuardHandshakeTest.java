package de.einesel.guardian;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class GuardHandshakeTest {
    private static final byte[] HELLO = "{\"protocol\":1,\"version\":\"1.0.2\"}".getBytes(StandardCharsets.UTF_8);
    private static final byte[] REPORT = "report".getBytes(StandardCharsets.UTF_8);

    @Test void remembersHelloBeforeConfigurationStarts() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveHello(HELLO);
        assertArrayEquals(REPORT, handshake.awaitReport(100, 100, () -> handshake.receiveReport(REPORT)));
    }
    @Test void doesNotSendChallengeBeforeClientIsReady() throws Exception {
        GuardHandshake handshake = new GuardHandshake();
        CompletableFuture<Void> started = new CompletableFuture<>();
        AtomicBoolean sent = new AtomicBoolean();
        var result = CompletableFuture.supplyAsync(() -> {
            started.complete(null);
            return handshake.awaitReport(2000, 1000, () -> { sent.set(true); handshake.receiveReport(REPORT); });
        });
        started.get(1, TimeUnit.SECONDS);
        assertFalse(sent.get());
        handshake.receiveHello(HELLO);
        assertArrayEquals(REPORT, result.get(1, TimeUnit.SECONDS));
        assertTrue(sent.get());
    }
    @Test void missingModTimesOutBeforeChallenge() {
        GuardHandshake handshake = new GuardHandshake();
        AtomicBoolean sent = new AtomicBoolean();
        assertThrows(TimeoutException.class, () -> handshake.awaitReport(10, 1000, () -> sent.set(true)));
        assertFalse(sent.get());
    }
    @Test void scanTimeoutIsSeparateFromReadiness() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveHello(HELLO);
        assertThrows(TimeoutException.class, () -> handshake.awaitReport(100, 10, () -> {}));
        assertTrue(handshake.isReady());
    }
    @Test void ignoresReportBeforeChallenge() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveReport(REPORT);
        handshake.receiveHello(HELLO);
        assertThrows(TimeoutException.class, () -> handshake.awaitReport(100, 10, () -> {}));
    }
    @Test void rejectsOldClientHello() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveHello("{\"protocol\":1,\"version\":\"1.0.0\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(ExecutionException.class, () -> handshake.awaitReport(100, 100, () -> fail("Challenge sent to old client")));
    }
    @Test void rejectsMalformedHello() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveHello("{}".getBytes(StandardCharsets.UTF_8));
        assertThrows(ExecutionException.class, () -> handshake.awaitReport(100, 100, () -> fail()));
    }
    @Test void oversizedReportFailsWithoutWaitingForTimeout() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.receiveHello(HELLO);
        assertThrows(ExecutionException.class, () -> handshake.awaitReport(100, 1000, () -> handshake.receiveReport(new byte[30001])));
    }
    @Test void connectionCloseUnblocksWaiter() {
        GuardHandshake handshake = new GuardHandshake();
        handshake.close();
        assertThrows(ExecutionException.class, () -> handshake.awaitReport(1000, 1000, () -> fail()));
    }
    @Test void separateConnectionsCannotShareReadinessOrReports() {
        GuardHandshake first = new GuardHandshake();
        GuardHandshake second = new GuardHandshake();
        first.receiveHello(HELLO);
        assertThrows(TimeoutException.class, () -> second.awaitReport(10, 100, () -> fail()));
        assertArrayEquals(REPORT, first.awaitReport(100, 100, () -> first.receiveReport(REPORT)));
    }
}
