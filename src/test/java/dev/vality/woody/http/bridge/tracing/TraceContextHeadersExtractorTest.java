package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.trace.TraceData;
import dev.vality.woody.api.trace.context.TraceContext;
import dev.vality.woody.http.bridge.token.TokenPayload;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class TraceContextHeadersExtractorTest {

    private SdkTracerProvider tracerProvider;

    @BeforeEach
    void setUp() {
        GlobalOpenTelemetry.resetForTest();
        tracerProvider = SdkTracerProvider.builder().build();
        final var openTelemetry = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .build();
        GlobalOpenTelemetry.set(openTelemetry);
    }

    @AfterEach
    void tearDown() {
        TraceContext.setCurrentTraceData(null);
        GlobalOpenTelemetry.resetForTest();
        if (tracerProvider != null) {
            tracerProvider.close();
        }
    }

    @Test
    void shouldExtractWoodyHeadersFromTraceContext() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var activeSpan = traceData.getActiveSpan();
        final var span = activeSpan.getSpan();
        span.setTraceId("trace-id");
        span.setId("span-id");
        span.setParentId("parent-id");
        span.setDeadline(Instant.parse("2030-01-01T00:00:00Z"));
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.ID, "user-id");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.USERNAME, "username");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.EMAIL, "user@example.com");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.REALM, "/realm");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertNotNull(headers);
        assertTrue(headers.containsKey(WOODY_TRACE_ID));
        assertTrue(headers.containsKey(WOODY_SPAN_ID));
        assertTrue(headers.containsKey(OTEL_TRACE_PARENT));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldExtractOnlyAvailableHeaders() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var activeSpan = traceData.getActiveSpan();
        final var span = activeSpan.getSpan();
        span.setTraceId("trace-id");
        span.setId("span-id");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertEquals("trace-id", headers.get(WOODY_TRACE_ID));
        assertEquals("span-id", headers.get(WOODY_SPAN_ID));
        assertNull(headers.get(WOODY_PARENT_ID));
        assertNull(headers.get(WOODY_DEADLINE));
        assertNull(headers.get(WOODY_META_ID));
        assertNotNull(headers.get(OTEL_TRACE_PARENT));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldIncludeRequestMetadata() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var serviceSpan = traceData.getServiceSpan().getSpan();
        serviceSpan.setTraceId("trace-id");
        serviceSpan.setId("span-id");
        traceData.getActiveSpan().getCustomMetadata().putValue(WoodyMetaHeaders.X_REQUEST_ID, "request-123");
        traceData.getActiveSpan().getCustomMetadata()
                .putValue(WoodyMetaHeaders.X_REQUEST_DEADLINE, "2030-12-31T23:59:59Z");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertEquals("request-123", headers.get(WOODY_META_REQUEST_ID));
        assertEquals("2030-12-31T23:59:59Z", headers.get(WOODY_META_REQUEST_DEADLINE));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldThrowWhenSpanContextIsInvalid() {
        final var traceData = new TraceData();
        TraceContext.setCurrentTraceData(traceData);

        try {
            TraceContextExtractor.extractHeaders();
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            // Expected
        }
    }

    @Test
    void shouldNotIncludeEmptyValues() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var activeSpan = traceData.getActiveSpan();
        final var span = activeSpan.getSpan();
        span.setTraceId("trace-id");
        span.setId("span-id");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.ID, "");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.USERNAME, null);

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertFalse(headers.containsKey(WOODY_META_ID));
        assertFalse(headers.containsKey(WOODY_META_USERNAME));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldExtractAllUserIdentityMetadata() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var activeSpan = traceData.getActiveSpan();
        final var span = activeSpan.getSpan();
        span.setTraceId("GZvsthKQAAA");
        span.setId("GZvsthKQBBB");
        span.setParentId("undefined");

        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.ID, "b54a93c4-415d-4f33-a5e9-3608fd043ff4");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.USERNAME, "noreply@valitydev.com");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.EMAIL, "noreply@valitydev.com");
        activeSpan.getCustomMetadata().putValue(WoodyMetaHeaders.REALM, "internal");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertEquals("b54a93c4-415d-4f33-a5e9-3608fd043ff4", headers.get(WOODY_META_ID));
        assertEquals("noreply@valitydev.com", headers.get(WOODY_META_USERNAME));
        assertEquals("noreply@valitydev.com", headers.get(WOODY_META_EMAIL));
        assertEquals("internal", headers.get(WOODY_META_REALM));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldGenerateValidTraceparent() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var span = traceData.getActiveSpan().getSpan();
        span.setTraceId("trace-id");
        span.setId("span-id");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        final String traceparent = headers.get(OTEL_TRACE_PARENT);
        assertNotNull(traceparent);
        assertTrue(traceparent.matches("00-[0-9a-f]{32}-[0-9a-f]{16}-0[0-1]"));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldExtractTokenPayloadFromTraceContext() {
        final var traceData = new TraceData();
        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var serviceSpan = traceData.getServiceSpan().getSpan();
        serviceSpan.setTraceId("11111111111111111111111111111111");
        serviceSpan.setId("2222222222222222");
        serviceSpan.setParentId("undefined");
        var timestamp = LocalDateTime.of(2025, 1, 1, 12, 0);

        final TokenPayload payload = TraceContextExtractor.extractTokenPayload(
                "https://example.com/callback",
                "invoice-1",
                timestamp
        );

        assertNotNull(payload);
        assertEquals("https://example.com/callback", payload.termUrl());
        assertEquals("invoice-1", payload.invoiceFormatPaymentId());
        assertEquals(timestamp, payload.timestamp());
        assertEquals("11111111111111111111111111111111", payload.traceId());
        assertEquals("2222222222222222", payload.spanId());
        assertNotNull(payload.newSpanId());
        assertFalse(payload.newSpanId().isBlank());
        assertNotEquals(payload.spanId(), payload.newSpanId());
        assertNotNull(payload.traceparent());
        assertFalse(payload.traceparent().isBlank());
        assertNull(payload.tracestate());

        traceData.finishOtelSpan();
    }

    @Test
    void shouldExtractComplexScenarioWithAllHeaders() {
        final var traceData = new TraceData();
        TraceContext.initNewServiceTrace(traceData, WFlow.createDefaultIdGenerator(), WFlow.createDefaultIdGenerator());

        attachOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        final var activeSpan = traceData.getActiveSpan();
        final var span = activeSpan.getSpan();
        span.setTraceId("GZyWNGugAAA");
        span.setId("GZyWNGugBBB");
        span.setParentId("undefined");
        span.setDeadline(Instant.parse("2030-01-01T00:00:00Z"));

        final var metadata = activeSpan.getCustomMetadata();
        metadata.putValue(WoodyMetaHeaders.ID, "b54a93c4-415d-4f33-a5e9-3608fd043ff4");
        metadata.putValue(WoodyMetaHeaders.USERNAME, "noreply@valitydev.com");
        metadata.putValue(WoodyMetaHeaders.EMAIL, "noreply@valitydev.com");
        metadata.putValue(WoodyMetaHeaders.REALM, "internal");
        metadata.putValue(WoodyMetaHeaders.X_REQUEST_ID, "req-12345");
        metadata.putValue(WoodyMetaHeaders.X_REQUEST_DEADLINE, "2030-01-01T00:00:00Z");

        final Map<String, String> headers = TraceContextExtractor.extractHeaders();

        assertEquals("GZyWNGugAAA", headers.get(WOODY_TRACE_ID));
        assertEquals("GZyWNGugBBB", headers.get(WOODY_SPAN_ID));
        assertEquals("undefined", headers.get(WOODY_PARENT_ID));
        assertEquals("2030-01-01T00:00:00Z", headers.get(WOODY_DEADLINE));
        assertEquals("b54a93c4-415d-4f33-a5e9-3608fd043ff4", headers.get(WOODY_META_ID));
        assertEquals("noreply@valitydev.com", headers.get(WOODY_META_USERNAME));
        assertEquals("noreply@valitydev.com", headers.get(WOODY_META_EMAIL));
        assertEquals("internal", headers.get(WOODY_META_REALM));
        assertEquals("req-12345", headers.get(WOODY_META_REQUEST_ID));
        assertEquals("2030-01-01T00:00:00Z", headers.get(WOODY_META_REQUEST_DEADLINE));
        assertNotNull(headers.get(OTEL_TRACE_PARENT));

        traceData.finishOtelSpan();
    }

    @Test
    void shouldFailWhenTraceContextMissing() {
        TraceContext.setCurrentTraceData(null);

        assertThrows(IllegalStateException.class, TraceContextExtractor::extractHeaders);
    }

    @Test
    void shouldThrowWhenOtelSpanIsNull() {
        final var traceData = new TraceData();
        clearOtelSpan(traceData);
        TraceContext.setCurrentTraceData(traceData);

        assertThrows(NullPointerException.class, TraceContextExtractor::extractHeaders);
    }

    private void attachOtelSpan(TraceData traceData) {
        traceData.startNewOtelSpan("test-span", SpanKind.SERVER, null);
    }

    private void clearOtelSpan(TraceData traceData) {
        try {
            Field field = TraceData.class.getDeclaredField("otelSpan");
            field.setAccessible(true);
            field.set(traceData, null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
