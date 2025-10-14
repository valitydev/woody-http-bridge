package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.trace.TraceData;
import dev.vality.woody.api.trace.context.TraceContext;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class TraceContextRestorerTest {

    private SdkTracerProvider tracerProvider;

    @BeforeEach
    void setUp() {
        GlobalOpenTelemetry.resetForTest();
        tracerProvider = SdkTracerProvider.builder().build();
        var openTelemetry = OpenTelemetrySdk.builder()
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
    void shouldRestoreWoodyTraceHeaders() {
        var headers = Map.of(
                WOODY_TRACE_ID, "GZyWNGugAAA",
                WOODY_SPAN_ID, "GZyWNGugBBB",
                WOODY_PARENT_ID, "undefined",
                WOODY_DEADLINE, "2030-01-01T00:00:00Z"
        );

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertNotNull(traceData);
        var span = traceData.getServiceSpan().getSpan();
        assertEquals("GZyWNGugAAA", span.getTraceId());
        assertEquals("GZyWNGugBBB", span.getId());
        assertEquals("undefined", span.getParentId());
        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), span.getDeadline());
        assertTrue(traceData.getOtelSpan().getSpanContext().isValid());
        assertNotNull(traceData.getOtelSpan().getSpanContext().getTraceId());
    }

    @Test
    void shouldRestoreUserIdentityMetadata() {
        var headers = new HashMap<String, String>();
        headers.put(WOODY_TRACE_ID, "trace-123");
        headers.put(WOODY_META_ID, "b54a93c4-415d-4f33-a5e9-3608fd043ff4");
        headers.put(WOODY_META_USERNAME, "noreply@valitydev.com");
        headers.put(WOODY_META_EMAIL, "noreply@valitydev.com");
        headers.put(WOODY_META_REALM, "/internal");

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        var metadata = traceData.getActiveSpan().getCustomMetadata();
        assertEquals("b54a93c4-415d-4f33-a5e9-3608fd043ff4", metadata.getValue(WoodyMetaHeaders.ID));
        assertEquals("noreply@valitydev.com", metadata.getValue(WoodyMetaHeaders.USERNAME));
        assertEquals("noreply@valitydev.com", metadata.getValue(WoodyMetaHeaders.EMAIL));
        assertEquals("/internal", metadata.getValue(WoodyMetaHeaders.REALM));
    }

    @Test
    void shouldRestoreOtelTraceParent() {
        var headers = Map.of(
                OTEL_TRACE_PARENT, "00-3d8202ad198e4d37771c995246e1b356-9cfa814ae977266e-01",
                OTEL_TRACE_STATE, "congo=t61rcWkgMzE"
        );

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertEquals("00-3d8202ad198e4d37771c995246e1b356-9cfa814ae977266e-01", traceData.getInboundTraceParent());
        assertEquals("congo=t61rcWkgMzE", traceData.getInboundTraceState());
        assertTrue(traceData.getOtelSpan().getSpanContext().isValid());
    }

    @Test
    void shouldHandleEmptyHeadersGracefully() {
        TraceData traceData = TraceContextRestorer.restoreTraceData(Map.of());
        assertNotNull(traceData);
        assertTrue(traceData.getServiceSpan().getSpan().isFilled());
        assertTrue(traceData.getOtelSpan().getSpanContext().isValid());
    }

    @Test
    void shouldRestoreDeadlineFromHeaders() {
        var headers = new HashMap<String, String>();
        headers.put(WOODY_TRACE_ID, "trace-123");
        headers.put(WOODY_DEADLINE, "2030-01-01T00:00:00Z");

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), traceData.getServiceSpan().getSpan().getDeadline());
    }

    @Test
    void shouldRestoreMetadataWithDeadlineFallback() {
        var headers = new HashMap<String, String>();
        headers.put(WOODY_TRACE_ID, "GZyWNGugAAA");
        headers.put(WOODY_SPAN_ID, "GZyWNGugBBB");
        headers.put(WOODY_PARENT_ID, "undefined");
        headers.put(WOODY_META_REQUEST_ID, "req-12345");
        headers.put(WOODY_META_REQUEST_DEADLINE, "2030-01-01T00:00:00Z");

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertEquals(
                "req-12345",
                traceData.getActiveSpan().getCustomMetadata().getValue(WoodyMetaHeaders.X_REQUEST_ID)
        );
        assertEquals("2030-01-01T00:00:00Z",
                traceData.getActiveSpan().getCustomMetadata().getValue(WoodyMetaHeaders.X_REQUEST_DEADLINE));
    }

    @Test
    void shouldNotFailWhenTraceParentInvalid() {
        var headers = Map.of(OTEL_TRACE_PARENT, "invalid");

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertNotNull(traceData);
        assertTrue(traceData.getServiceSpan().getSpan().isFilled());
    }

    @Test
    void shouldRestoreWithPreExistingTraceData() {
        var headers = Map.of(
                WOODY_TRACE_ID, "trace-123",
                WOODY_SPAN_ID, "span-456"
        );

        var existing = new TraceData();
        TraceContext.setCurrentTraceData(existing);

        TraceData traceData = TraceContextRestorer.restoreTraceData(headers);

        assertNotNull(traceData.getServiceSpan());
        assertEquals("trace-123", traceData.getServiceSpan().getSpan().getTraceId());
        assertEquals("span-456", traceData.getServiceSpan().getSpan().getId());
    }

}
