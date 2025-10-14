package dev.vality.woody.http.bridge;

import dev.vality.woody.api.trace.context.TraceContext;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.context.propagation.TextMapSetter;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static dev.vality.woody.http.bridge.TraceHeadersConstants.*;

@Slf4j
@UtilityClass
public class TraceContextHeadersExtractor {

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

    private void putIfNotNull(Map<String, String> headers,
                              String key,
                              String value) {
        if (value != null && !value.isEmpty()) {
            headers.put(key, value);
        }
    }

    private static final TextMapSetter<Map<String, String>> MAP_SETTER = (carrier, key, value) -> {
        if (carrier != null && key != null && value != null && !value.isEmpty()) {
            carrier.put(key, value);
        }
    };
}
