package dev.vality.woody.http.bridge.token;

import java.time.LocalDateTime;

public record TokenPayload(String termUrl,
                           LocalDateTime timestamp,
                           String invoiceFormatPaymentId,
                           String traceId,
                           String spanId,
                           String newSpanId,
                           String traceparent,
                           String tracestate) {
}
