package dev.vality.woody.http.bridge.token;

import lombok.Getter;

import java.time.LocalDateTime;

//  todo String tracestate
public record TokenPayload(String termUrl, LocalDateTime timestamp, String invoiceFormatPaymentId,
                           String traceId, String spanId, String newSpanId, String traceparent) {
}
