package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.generator.IdGenerator;
import dev.vality.woody.api.trace.TraceData;
import dev.vality.woody.api.trace.context.TraceContext;
import dev.vality.woody.http.bridge.token.TokenPayload;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.context.propagation.TextMapSetter;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;

@Slf4j
@UtilityClass
public class TraceContextExtractor {

    public Map<String, String> extractHeaders() {
        var traceData = Objects.requireNonNull(TraceContext.getCurrentTraceData(),
                "TraceData should be present in TraceContext");
        var otelSpan = Objects.requireNonNull(traceData.getOtelSpan(),
                "OTel span should be attached to TraceData");
        if (!otelSpan.getSpanContext().isValid()) {
            throw new IllegalStateException("SpanContext must be valid");
        }

        var span = traceData.getActiveSpan().getSpan();
        var headers = new HashMap<String, String>();
        putIfNotNull(headers, WOODY_TRACE_ID, span.getTraceId());
        putIfNotNull(headers, WOODY_SPAN_ID, span.getId());
        putIfNotNull(headers, WOODY_PARENT_ID, span.getParentId());
        putIfNotNull(headers, WOODY_DEADLINE,
                Optional.ofNullable(span.getDeadline()).map(Instant::toString).orElse(null));
        var customMetadata = traceData.getActiveSpan().getCustomMetadata();
        customMetadata.getKeys()
                .forEach(s -> putIfNotNull(headers, WOODY_META_PREFIX + s, customMetadata.getValue(s)));
        GlobalOpenTelemetry.getPropagators()
                .getTextMapPropagator()
                .inject(traceData.getOtelContext(), headers, MAP_SETTER);
        log.debug("Extracted trace headers: {}", headers);
        return headers;
    }

    public TokenPayload extractTokenPayload(String termUrl,
                                            String invoiceFormatPaymentId) {
        return extractTokenPayload(termUrl, invoiceFormatPaymentId, LocalDateTime.now(ZoneOffset.UTC));
    }

    public TokenPayload extractTokenPayload(String termUrl,
                                            String invoiceFormatPaymentId,
                                            LocalDateTime timestamp) {
        var traceData = Objects.requireNonNull(TraceContext.getCurrentTraceData(),
                "TraceData should be present in TraceContext");
        var otelSpan = Objects.requireNonNull(traceData.getOtelSpan(),
                "OTel span should be attached to TraceData");
        if (!otelSpan.getSpanContext().isValid()) {
            throw new IllegalStateException("SpanContext must be valid");
        }

        var span = traceData.getActiveSpan().getSpan();
        var traceId = span.getTraceId();
        var spanId = span.getId();

        var carrier = new HashMap<String, String>();
        GlobalOpenTelemetry.getPropagators()
                .getTextMapPropagator()
                .inject(traceData.getOtelContext(), carrier, MAP_SETTER);
        var traceparent = carrier.get(OTEL_TRACE_PARENT);
        var tracestate = carrier.get(OTEL_TRACE_STATE);

        return new TokenPayload(
                termUrl,
                timestamp != null ? timestamp : LocalDateTime.now(ZoneOffset.UTC),
                invoiceFormatPaymentId,
                traceId,
                spanId,
                generateSpanId(traceData),
                traceparent,
                tracestate
        );
    }

    private void putIfNotNull(Map<String, String> headers,
                              String key,
                              String value) {
        if (value != null && !value.isEmpty()) {
            headers.put(key, value);
        }
    }

    private String generateSpanId(TraceData traceData) {
        var root = traceData.isRoot();
        var defaultIdGenerator = WFlow.createDefaultIdGenerator();
        if (root) {
            return defaultIdGenerator.generateId();
        } else {
            return defaultIdGenerator.generateId("", traceData.getServiceSpan().getCounter().incrementAndGet());
        }
    }

    private static final TextMapSetter<Map<String, String>> MAP_SETTER = (carrier, key, value) -> {
        if (carrier != null && key != null && value != null && !value.isEmpty()) {
            carrier.put(key, value);
        }
    };
}
