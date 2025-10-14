package dev.vality.woody.http.bridge;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.trace.TraceData;
import dev.vality.woody.api.trace.context.TraceContext;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.TextMapGetter;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.function.Consumer;

import static dev.vality.woody.http.bridge.TraceHeadersConstants.*;

@Slf4j
@UtilityClass
public class TraceContextRestorer {

    public TraceData restoreTraceData(Map<String, String> headers) {
        log.debug("Restoring trace data from headers: {}", headers);
        var traceData = TraceContext.initNewServiceTrace(new TraceData(),
                WFlow.createDefaultIdGenerator(), WFlow.createDefaultIdGenerator());
        if (headers.isEmpty()) {
            return traceData;
        }
        var span = traceData.getActiveSpan().getSpan();
        setIfPresent(headers, WOODY_TRACE_ID, span::setTraceId);
        setIfPresent(headers, WOODY_SPAN_ID, span::setId);
        setIfPresent(headers, WOODY_PARENT_ID, span::setParentId);
        setIfPresent(headers, WOODY_DEADLINE, value -> span.setDeadline(Instant.parse(value)));
        span.setTimestamp(0);
        span.setDuration(0);
        var customMetadata = traceData.getActiveSpan().getCustomMetadata();
        headers.keySet()
                .stream()
                .filter(s -> s.startsWith(WOODY_META_PREFIX))
                .forEach(s -> {
                    var metaKey = s.substring(WOODY_META_PREFIX.length());
                    setIfPresent(headers, s, value -> customMetadata.putValue(metaKey, value));
                });
        var extracted = GlobalOpenTelemetry.getPropagators()
                .getTextMapPropagator()
                .extract(Context.root(), headers, HEADER_GETTER);
        if (io.opentelemetry.api.trace.Span.fromContext(extracted).getSpanContext().isValid()) {
            traceData.setPendingParentContext(extracted);
            traceData.setInboundTraceParent(headers.get(OTEL_TRACE_PARENT));
            traceData.setInboundTraceState(headers.getOrDefault(OTEL_TRACE_STATE, null));
        }
        return traceData;
    }

    private void setIfPresent(Map<String, String> headers, String key, Consumer<String> consumer) {
        var value = headers.get(key);
        if (value != null && !value.isEmpty()) {
            try {
                consumer.accept(value);
            } catch (Exception e) {
                log.warn("Unable to set header with  key '{}' value '{}'", key, value);
            }
        }
    }

    private static final TextMapGetter<Map<String, String>> HEADER_GETTER = new TextMapGetter<>() {
        @Override
        public Iterable<String> keys(Map<String, String> carrier) {
            return carrier.keySet();
        }

        @Override
        public String get(Map<String, String> carrier, String key) {
            return carrier.get(key);
        }
    };
}
