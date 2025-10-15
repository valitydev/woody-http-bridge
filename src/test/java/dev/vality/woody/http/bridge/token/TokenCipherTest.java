package dev.vality.woody.http.bridge.token;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

class TokenCipherTest {

    private final TokenCipher tokenCipher = new TokenCipher();

    private TokenPayload samplePayload() {
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

    @Test
    void shouldEncryptAndDecryptPayload() {
        var token = tokenCipher.encrypt(samplePayload(), "secret-key");
        var decrypted = tokenCipher.decrypt(token, "secret-key");

        assertEquals(samplePayload(), decrypted);
    }

    @Test
    void shouldFailWithWrongSecretKey() {
        var token = tokenCipher.encrypt(samplePayload(), "secret-key");

        var error = assertThrows(IllegalArgumentException.class,
                () -> tokenCipher.decrypt(token, "another-key"));
        assertEquals("Wrong secret key", error.getMessage());
    }

    @Test
    void shouldRejectInvalidTokenString() {
        assertThrows(IllegalArgumentException.class, () -> tokenCipher.decrypt("not-valid", "secret-key"));
    }
}
