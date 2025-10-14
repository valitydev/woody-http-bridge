package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.trace.context.TraceContext;
import dev.vality.woody.http.bridge.tracing.TraceContextHeadersExtractor;
import dev.vality.woody.http.bridge.tracing.TraceContextRestorer;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;
import static org.junit.jupiter.api.Assertions.*;

class TraceContextPipelineTest {

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
    void shouldRestoreAndExtractTraceContextWithinWFlow() {
        var normalized = new HashMap<String, String>();
        normalized.put(WOODY_TRACE_ID, "GZyWNGugAAA");
        normalized.put(WOODY_SPAN_ID, "GZyWNGugBBB");
        normalized.put(WOODY_PARENT_ID, "undefined");
        normalized.put(WOODY_DEADLINE, "2030-01-01T00:00:00Z");
        var otelTraceId = "3d8202ad198e4d37771c995246e1b356";
        normalized.put(OTEL_TRACE_PARENT, "00-" + otelTraceId + "-9cfa814ae977266e-01");
        normalized.put(WOODY_META_ID, "user-id");
        normalized.put(WOODY_META_USERNAME, "user-name");
        normalized.put(WOODY_META_EMAIL, "user@example.com");
        normalized.put(WOODY_META_REALM, "/internal");
        normalized.put(WOODY_META_REQUEST_ID, "request-id");
        normalized.put(WOODY_META_REQUEST_DEADLINE, "2030-01-01T00:00:00Z");

        var traceData = TraceContextRestorer.restoreTraceData(normalized);
        assertTrue(traceData.getServiceSpan().getSpan().isFilled());
        assertFalse(traceData.isClient());
        var extractedRef = new AtomicReference<Map<String, String>>();

        WFlow.create(() -> {
            var current = TraceContext.getCurrentTraceData();
            assertNotNull(current);
            assertTrue(current.getServiceSpan().getSpan().isFilled());
            assertFalse(current.isClient());
            extractedRef.set(TraceContextHeadersExtractor.extractHeaders());
        }, traceData).run();

        var extracted = extractedRef.get();
        assertNotNull(extracted);
        assertEquals("GZyWNGugAAA", extracted.get(WOODY_TRACE_ID));
        assertEquals("GZyWNGugBBB", extracted.get(WOODY_SPAN_ID));
        assertEquals("undefined", extracted.get(WOODY_PARENT_ID));
        assertEquals("2030-01-01T00:00:00Z", extracted.get(WOODY_DEADLINE));
        assertEquals("user-id", extracted.get(WOODY_META_ID));
        assertEquals("user-name", extracted.get(WOODY_META_USERNAME));
        assertEquals("user@example.com", extracted.get(WOODY_META_EMAIL));
        assertEquals("/internal", extracted.get(WOODY_META_REALM));
        assertEquals("request-id", extracted.get(WOODY_META_REQUEST_ID));
        assertEquals("2030-01-01T00:00:00Z", extracted.get(WOODY_META_REQUEST_DEADLINE));
        assertTrue(extracted.get(OTEL_TRACE_PARENT).contains(otelTraceId));
    }
}
