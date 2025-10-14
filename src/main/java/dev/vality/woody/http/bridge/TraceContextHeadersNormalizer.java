package dev.vality.woody.http.bridge;

import dev.vality.woody.http.bridge.JwtTokenDetailsExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static dev.vality.woody.http.bridge.TraceHeadersConstants.*;
import static dev.vality.woody.http.bridge.DeadlineUtil.*;

@Slf4j
@UtilityClass
public class TraceContextHeadersNormalizer {

    public Map<String, String> normalize(HttpServletRequest request) {
        var normalized = new HashMap<String, String>();
        normalizeWoodyHeaders(request, normalized);
        normalizeOtelHeaders(request, normalized);
        mergeJwtIntoHeaders(normalized);
        mergeRequestDeadline(request, normalized);
        return normalized.isEmpty() ? Map.of() : Map.copyOf(normalized);
    }

    public HttpHeaders normalizeResponseHeaders(HttpHeaders responseHeaders) {
        var normalized = new HttpHeaders();
        for (var entry : responseHeaders.entrySet()) {
            var headerName = entry.getKey();
            var lowerCase = headerName.toLowerCase(Locale.ROOT);
            if (lowerCase.startsWith(WOODY_PREFIX)) {
                normalizeWoodyResponseHeader(normalized, lowerCase, entry.getValue());
            } else if (lowerCase.equals(OTEL_TRACE_STATE.toLowerCase(Locale.ROOT))
                    || lowerCase.equals(OTEL_TRACE_PARENT.toLowerCase(Locale.ROOT))) {
                normalized.addAll(headerName, entry.getValue());
            }
        }
        return normalized;
    }

    private void normalizeWoodyHeaders(HttpServletRequest request, Map<String, String> headers) {
        (request.getHeaderNames() != null ? Collections.list(request.getHeaderNames()) : new ArrayList<String>())
                .stream()
                .map(s -> s.toLowerCase(Locale.ROOT))
                .filter(s -> s.startsWith(WOODY_PREFIX) || s.startsWith(ExternalHeaders.X_WOODY_PREFIX))
                .forEach(s -> {
                    if (s.startsWith(ExternalHeaders.X_WOODY_META_PREFIX)) {
                        var metaKey = s.substring(ExternalHeaders.X_WOODY_META_PREFIX.length());
                        if (metaKey.startsWith(ExternalHeaders.XWoodyMetaHeaders.USER_IDENTITY_PREFIX)) {
                            var userIdentityKey =
                                    metaKey.substring(ExternalHeaders.XWoodyMetaHeaders.USER_IDENTITY_PREFIX.length());
                            putIfNotNull(headers,
                                    WOODY_META_PREFIX + WoodyMetaHeaders.USER_IDENTITY_PREFIX + userIdentityKey,
                                    request.getHeader(s));
                        } else {
                            putIfNotNull(headers, WOODY_META_PREFIX + metaKey, request.getHeader(s));
                        }
                    } else if (s.startsWith(ExternalHeaders.X_WOODY_PREFIX)) {
                        putIfNotNull(headers, WOODY_PREFIX + s.substring(ExternalHeaders.X_WOODY_PREFIX.length()),
                                request.getHeader(s));
                    } else if (s.startsWith(WOODY_PREFIX)) {
                        putIfNotNull(headers, s, request.getHeader(s));
                    }
                });
        putIfNotNull(headers, WOODY_META_REQUEST_ID, request.getHeader(ExternalHeaders.X_REQUEST_ID));
        putIfNotNull(headers, WOODY_META_REQUEST_DEADLINE, request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE));
        putIfNotNull(headers, WOODY_META_REQUEST_INVOICE_ID, request.getHeader(ExternalHeaders.X_INVOICE_ID));
    }

    private void normalizeWoodyResponseHeader(HttpHeaders headers,
                                              String lowerCase,
                                              List<String> values) {
        if (lowerCase.startsWith(WOODY_META_PREFIX)) {
            var metaKey = lowerCase.substring(WOODY_META_PREFIX.length());
            if (metaKey.startsWith(WoodyMetaHeaders.USER_IDENTITY_PREFIX)) {
                if (metaKey.equals(WoodyMetaHeaders.X_REQUEST_ID.toLowerCase(Locale.ROOT))) {
                    headers.addAll(ExternalHeaders.X_REQUEST_ID, values);
                } else if (metaKey.equals(WoodyMetaHeaders.X_REQUEST_DEADLINE.toLowerCase(Locale.ROOT))) {
                    headers.addAll(ExternalHeaders.X_REQUEST_DEADLINE, values);
                } else if (metaKey.equals(WoodyMetaHeaders.X_INVOICE_ID.toLowerCase(Locale.ROOT))) {
                    headers.addAll(ExternalHeaders.X_INVOICE_ID, values);
                } else {
                    var userIdentityKey = metaKey.substring(WoodyMetaHeaders.USER_IDENTITY_PREFIX.length());
                    headers.addAll(
                            ExternalHeaders.X_WOODY_META_PREFIX +
                                    ExternalHeaders.XWoodyMetaHeaders.USER_IDENTITY_PREFIX +
                                    userIdentityKey, values);
                }
            } else {
                headers.addAll(ExternalHeaders.X_WOODY_META_PREFIX + metaKey, values);
            }
        } else {
            headers.addAll(ExternalHeaders.X_WOODY_PREFIX + lowerCase.substring(WOODY_PREFIX.length()), values);
        }
    }

    private void normalizeOtelHeaders(HttpServletRequest request, Map<String, String> headers) {
        putIfNotNull(headers, OTEL_TRACE_PARENT, request.getHeader(OTEL_TRACE_PARENT));
        putIfNotNull(headers, OTEL_TRACE_STATE, request.getHeader(OTEL_TRACE_STATE));
    }

    private void mergeJwtIntoHeaders(Map<String, String> headers) {
        var tokenDetails = JwtTokenDetailsExtractor.extractFromContext(SecurityContextHolder
                .getContext()
                .getAuthentication());
        if (tokenDetails.isEmpty()) {
            return;
        }
        var details = tokenDetails.get();
        putIfNotNull(headers, WOODY_META_ID, details.subject());
        putIfNotNull(headers, WOODY_META_USERNAME, details.preferredUsername());
        putIfNotNull(headers, WOODY_META_EMAIL, details.email());
        putIfNotNull(headers, WOODY_META_REALM, details.realm());
    }

    private void mergeRequestDeadline(HttpServletRequest request, Map<String, String> headers) {
        var requestDeadlineHeader = request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE);
        var requestIdHeader = request.getHeader(ExternalHeaders.X_REQUEST_ID);
        if (requestDeadlineHeader == null) {
            return;
        }
        try {
            var normalizedDeadline = getInstant(requestDeadlineHeader, requestIdHeader).toString();
            headers.putIfAbsent(WOODY_DEADLINE, normalizedDeadline);
            headers.put(WOODY_META_REQUEST_DEADLINE, normalizedDeadline);
        } catch (Exception e) {
            log.warn("Unable to parse '" + ExternalHeaders.X_REQUEST_DEADLINE + "' header value '{}'",
                    requestDeadlineHeader);
        }
    }

    private void putIfNotNull(Map<String, String> headers,
                              String key,
                              String value) {
        if (value != null && !value.isEmpty()) {
            headers.put(key, value);
        }
    }

    private Instant getInstant(String requestDeadlineHeader, String requestIdHeader) {
        if (containsRelativeValues(requestDeadlineHeader, requestIdHeader)) {
            return Instant.now()
                    .plus(extractMilliseconds(requestDeadlineHeader, requestIdHeader), ChronoUnit.MILLIS)
                    .plus(extractSeconds(requestDeadlineHeader, requestIdHeader), ChronoUnit.MILLIS)
                    .plus(extractMinutes(requestDeadlineHeader, requestIdHeader), ChronoUnit.MILLIS);
        }
        return Instant.parse(requestDeadlineHeader);
    }
}
