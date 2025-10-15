package dev.vality.woody.http.bridge.token;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class TokenCipherTest {

    private static final String SECRET_KEY = "secret-key";
    private static final String TOKEN_PATTERN = "^[A-Za-z0-9_-]+$";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int TAG_LENGTH_BYTES = 16;

    private final TokenCipher tokenCipher = new TokenCipher();

    @Test
    void shouldEncryptAndDecryptPayload() {
        var token = tokenCipher.encrypt(baselinePayload(), SECRET_KEY);
        var decrypted = tokenCipher.decrypt(token, SECRET_KEY);

        assertEquals(baselinePayload(), decrypted);
    }

    @Test
    void shouldProduceDifferentTokensForSamePayload() {
        var first = tokenCipher.encrypt(baselinePayload(), SECRET_KEY);
        var second = tokenCipher.encrypt(baselinePayload(), SECRET_KEY);

        assertNotEquals(first, second);
        assertTrue(first.matches(TOKEN_PATTERN));
        assertTrue(second.matches(TOKEN_PATTERN));
    }

    @Test
    void shouldKeepTokenWithinPartnerUrlLimit() {
        var prefix = "https://wrapper.pcigate.tech/16fef39e8e6bfdb777b6b46e92ecd83bc8dafa7c/v1/callback/";
        var token = tokenCipher.encrypt(baselinePayload(), SECRET_KEY);

        var fullLength = prefix.length() + token.length();
        var decoded = Base64.getUrlDecoder().decode(token);
        var payloadBytes = decoded.length - IV_LENGTH_BYTES - TAG_LENGTH_BYTES;

        assertTrue(fullLength <= 255, () -> "full URL length %d (prefix=%d, token=%d, payloadBytes=%d)".formatted(
                fullLength, prefix.length(), token.length(), payloadBytes));
        assertTrue(payloadBytes > 0);
    }

    @Test
    void shouldFailWithWrongSecretKey() {
        var token = tokenCipher.encrypt(baselinePayload(), SECRET_KEY);

        var error = assertThrows(IllegalArgumentException.class,
                () -> tokenCipher.decrypt(token, "another-key"));
        assertEquals("Wrong secret key", error.getMessage());
    }

    @Test
    void shouldRejectInvalidTokenString() {
        assertThrows(IllegalArgumentException.class, () -> tokenCipher.decrypt("not-valid", SECRET_KEY));
    }

    @Test
    void shouldHandleNullTracestate() {
        var payload = new TokenPayload(
                "https://example.com",
                LocalDateTime.of(2024, 10, 15, 12, 0, 0),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                null
        );

        var token = tokenCipher.encrypt(payload, SECRET_KEY);
        var decrypted = tokenCipher.decrypt(token, SECRET_KEY);

        assertNull(decrypted.tracestate());
        assertEquals(payload.traceparent(), decrypted.traceparent());
    }

    @Test
    void shouldTruncateTimestampToMinutes() {
        var original = LocalDateTime.parse("2025-10-09T10:23:36.534210601");
        var token = tokenCipher.encrypt(withTimestamp(original), SECRET_KEY);

        var decrypted = tokenCipher.decrypt(token, SECRET_KEY);

        assertEquals(original.truncatedTo(ChronoUnit.MINUTES), decrypted.timestamp());
    }

    @Test
    void shouldPreserveMinuteComponentAcrossExamples() {
        var cases = new String[] {
                "2025-10-09T10:23:00",
                "2025-10-09T10:23:36",
                "2025-10-09T10:23:59",
                "2025-10-09T23:59:59"
        };

        for (var time : cases) {
            var original = LocalDateTime.parse(time);
            var token = tokenCipher.encrypt(withTimestamp(original), SECRET_KEY);
            var decrypted = tokenCipher.decrypt(token, SECRET_KEY);

            assertEquals(original.truncatedTo(ChronoUnit.MINUTES), decrypted.timestamp(), "Failed for " + time);
        }
    }

    private TokenPayload baselinePayload() {
        return new TokenPayload(
                "https://example.com",
                LocalDateTime.of(2024, 10, 15, 12, 0, 0),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                "key=value"
        );
    }

    private TokenPayload withTimestamp(LocalDateTime timestamp) {
        var base = baselinePayload();
        return new TokenPayload(
                base.termUrl(),
                timestamp,
                base.invoiceFormatPaymentId(),
                base.traceId(),
                base.spanId(),
                base.newSpanId(),
                base.traceparent(),
                base.tracestate()
        );
    }
}
