package dev.vality.woody.http.bridge.service;

import dev.vality.adapter.common.secret.SecretObj;
import dev.vality.adapter.common.secret.SecretRef;
import dev.vality.adapter.common.secret.SecretValue;
import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.token.TokenPayload;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Slf4j
public record SecretService(VaultSecretService vaultSecretService, String serviceName) {

    private static final String SECRET_KEY = "secret_key";
    private static final String CIPHER_TOKEN = "cipher_token";
    private static final String FIELD_TERM_URL = "term_url";
    private static final String FIELD_TIMESTAMP = "timestamp";
    private static final String FIELD_INVOICE_PAYMENT_ID = "invoice_format_payment_id";
    private static final String FIELD_TRACE_ID = "trace_id";
    private static final String FIELD_SPAN_ID = "span_id";
    private static final String FIELD_NEW_SPAN_ID = "new_span_id";
    private static final String FIELD_TRACEPARENT = "traceparent";
    private static final String FIELD_TRACESTATE = "tracestate";
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    public String getCipherTokenSecretKey() {
        return vaultSecretService.getSecret(serviceName, new SecretRef(CIPHER_TOKEN, SECRET_KEY)).getValue();
    }

    public TokenPayload getVaultToken(String tokenKey) {
        Objects.requireNonNull(tokenKey, "tokenKey must not be null");
        var secrets = vaultSecretService.getSecrets(serviceName, tokenKey);
        if (secrets == null || secrets.isEmpty()) {
            log.warn("Vault secret '{}' for service '{}' is empty", tokenKey, serviceName);
            return null;
        }

        var termUrl = readValue(secrets, FIELD_TERM_URL);
        var timestamp = parseTimestamp(readValue(secrets, FIELD_TIMESTAMP));
        var invoicePaymentId = readValue(secrets, FIELD_INVOICE_PAYMENT_ID);
        var traceId = readValue(secrets, FIELD_TRACE_ID);
        var spanId = readValue(secrets, FIELD_SPAN_ID);
        var newSpanId = readValue(secrets, FIELD_NEW_SPAN_ID);
        var traceparent = readValue(secrets, FIELD_TRACEPARENT);
        var tracestate = readValue(secrets, FIELD_TRACESTATE);

        if (termUrl == null || traceId == null || spanId == null || newSpanId == null || traceparent == null) {
            log.warn("Vault secret '{}' for service '{}' missing required token fields", tokenKey, serviceName);
            return null;
        }

        return new TokenPayload(
                termUrl,
                timestamp,
                invoicePaymentId,
                traceId,
                spanId,
                newSpanId,
                traceparent,
                tracestate
        );
    }

    public void saveVaultToken(String tokenKey, TokenPayload payload) {
        Objects.requireNonNull(tokenKey, "tokenKey must not be null");
        Objects.requireNonNull(payload, "payload must not be null");

        var values = new HashMap<String, String>();
        putIfNotNull(values, FIELD_TERM_URL, payload.termUrl());
        if (payload.timestamp() != null) {
            values.put(FIELD_TIMESTAMP, TIMESTAMP_FORMATTER.format(payload.timestamp()));
        }
        putIfNotNull(values, FIELD_INVOICE_PAYMENT_ID, payload.invoiceFormatPaymentId());
        putIfNotNull(values, FIELD_TRACE_ID, payload.traceId());
        putIfNotNull(values, FIELD_SPAN_ID, payload.spanId());
        putIfNotNull(values, FIELD_NEW_SPAN_ID, payload.newSpanId());
        putIfNotNull(values, FIELD_TRACEPARENT, payload.traceparent());
        putIfNotNull(values, FIELD_TRACESTATE, payload.tracestate());

        vaultSecretService.writeSecret(serviceName, new SecretObj(tokenKey, values));
    }

    private String readValue(Map<String, SecretValue> secrets, String key) {
        var value = secrets.get(key);
        return value != null ? value.getValue() : null;
    }

    private LocalDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(value, TIMESTAMP_FORMATTER);
        } catch (DateTimeParseException ex) {
            log.warn("Failed to parse vault token timestamp '{}'", value, ex);
            return null;
        }
    }

    private void putIfNotNull(Map<String, String> values, String key, String value) {
        if (value != null) {
            values.put(key, value);
        }
    }
}
