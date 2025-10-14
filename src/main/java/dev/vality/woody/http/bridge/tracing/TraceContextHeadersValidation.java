package dev.vality.woody.http.bridge.tracing;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.LinkedHashMap;
import java.util.Map;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;

@Slf4j
@UtilityClass
public class TraceContextHeadersValidation {

    public LinkedHashMap<String, String> validate(Map<String, String> normalized) {
        var copy = new LinkedHashMap<>(normalized);
        var traceId = copy.get(WOODY_TRACE_ID);
        if (traceId != null && traceId.equals(copy.get(WOODY_SPAN_ID))) {
            copy.remove(WOODY_SPAN_ID);
        }
        if ("undefined".equals(copy.get(WOODY_PARENT_ID))) {
            copy.remove(WOODY_PARENT_ID);
        }
        return copy;
    }
}
