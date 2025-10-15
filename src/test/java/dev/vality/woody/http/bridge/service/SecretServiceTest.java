package dev.vality.woody.http.bridge.service;

import dev.vality.adapter.common.secret.SecretObj;
import dev.vality.adapter.common.secret.SecretRef;
import dev.vality.adapter.common.secret.SecretValue;
import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.token.TokenPayload;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class SecretServiceTest {

    private VaultSecretService vaultSecretService;
    private SecretService secretService;

    @BeforeEach
    void setUp() {
        vaultSecretService = mock(VaultSecretService.class);
        secretService = new SecretService(vaultSecretService, "test-service");
    }

    @Test
    void shouldCacheSecretKey() {
        when(vaultSecretService.getSecret(eq("test-service"), any(SecretRef.class)))
                .thenReturn(new SecretValue("cipher-secret"));

        var first = secretService.getCipherTokenSecretKey();
        var second = secretService.getCipherTokenSecretKey();

        assertEquals("cipher-secret", first);
        assertSame(first, second);
        verify(vaultSecretService, times(1)).getSecret(eq("test-service"), any(SecretRef.class));
    }

    @Test
    void shouldRestoreVaultToken() {
        var timestamp = LocalDateTime.of(2024, 10, 15, 12, 0, 0);
        var secrets = Map.of(
                "term_url", new SecretValue("https://example.com"),
                "timestamp", new SecretValue(timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME)),
                "invoice_format_payment_id", new SecretValue("invoice-1"),
                "trace_id", new SecretValue("11111111111111111111111111111111"),
                "span_id", new SecretValue("2222222222222222"),
                "new_span_id", new SecretValue("3333333333333333"),
                "traceparent", new SecretValue("00-11111111111111111111111111111111-2222222222222222-01"),
                "tracestate", new SecretValue("key=value")
        );
        when(vaultSecretService.getSecrets("test-service", "token-key")).thenReturn(secrets);

        var payload = secretService.getVaultToken("token-key");

        assertNotNull(payload);
        assertEquals("https://example.com", payload.termUrl());
        assertEquals(timestamp, payload.timestamp());
        assertEquals("invoice-1", payload.invoiceFormatPaymentId());
        assertEquals("11111111111111111111111111111111", payload.traceId());
        assertEquals("2222222222222222", payload.spanId());
        assertEquals("3333333333333333", payload.newSpanId());
        assertEquals("00-11111111111111111111111111111111-2222222222222222-01", payload.traceparent());
        assertEquals("key=value", payload.tracestate());
    }

    @Test
    void shouldReturnNullWhenVaultTokenIncomplete() {
        var secrets = Map.of(
                "term_url", new SecretValue("https://example.com"),
                "span_id", new SecretValue("2222222222222222"),
                "new_span_id", new SecretValue("3333333333333333"),
                "traceparent", new SecretValue("00-11111111111111111111111111111111-2222222222222222-01")
        );
        when(vaultSecretService.getSecrets("test-service", "token-key")).thenReturn(secrets);

        assertNull(secretService.getVaultToken("token-key"));
    }

    @Test
    void shouldHandleInvalidTimestampGracefully() {
        var secrets = new HashMap<String, SecretValue>();
        secrets.put("term_url", new SecretValue("https://example.com"));
        secrets.put("timestamp", new SecretValue("bad-timestamp"));
        secrets.put("invoice_format_payment_id", new SecretValue("invoice-1"));
        secrets.put("trace_id", new SecretValue("11111111111111111111111111111111"));
        secrets.put("span_id", new SecretValue("2222222222222222"));
        secrets.put("new_span_id", new SecretValue("3333333333333333"));
        secrets.put("traceparent", new SecretValue("00-11111111111111111111111111111111-2222222222222222-01"));
        secrets.put("tracestate", new SecretValue("key=value"));
        when(vaultSecretService.getSecrets("test-service", "token-key")).thenReturn(secrets);

        var payload = secretService.getVaultToken("token-key");

        assertNotNull(payload);
        assertNull(payload.timestamp());
    }

    @Test
    void shouldSaveVaultToken() {
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

        secretService.saveVaultToken("token-key", payload);

        var captor = ArgumentCaptor.forClass(SecretObj.class);
        verify(vaultSecretService).writeSecret(eq("test-service"), captor.capture());
        var saved = captor.getValue();

        assertEquals("token-key", saved.getPath());
        assertEquals("https://example.com", saved.getValues().get("term_url"));
        assertEquals("invoice-1", saved.getValues().get("invoice_format_payment_id"));
        assertEquals("11111111111111111111111111111111", saved.getValues().get("trace_id"));
        assertEquals("2222222222222222", saved.getValues().get("span_id"));
        assertEquals("3333333333333333", saved.getValues().get("new_span_id"));
        assertEquals("00-11111111111111111111111111111111-2222222222222222-01",
                saved.getValues().get("traceparent"));
        assertFalse(saved.getValues().containsKey("tracestate"));
        assertEquals("2024-10-15T12:00:00", saved.getValues().get("timestamp"));
    }
}
