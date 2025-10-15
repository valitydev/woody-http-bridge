package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.http.bridge.tracing.TraceContextHeadersNormalizer;
import dev.vality.woody.http.bridge.util.JwtTokenDetailsExtractor;
import dev.vality.woody.http.bridge.util.JwtTokenDetailsExtractor.JwtTokenDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TraceContextHeadersNormalizerTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        lenient().when(request.getHeader(WOODY_TRACE_ID)).thenReturn(null);
        lenient().when(request.getHeader(WOODY_SPAN_ID)).thenReturn(null);
        lenient().when(request.getHeader(WOODY_PARENT_ID)).thenReturn(null);
        lenient().when(request.getHeader(WOODY_DEADLINE)).thenReturn(null);
        lenient().when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);
        lenient().when(request.getHeader(OTEL_TRACE_STATE)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_WOODY_TRACE_ID)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_WOODY_SPAN_ID)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_WOODY_PARENT_ID)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_WOODY_DEADLINE)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn(null);
        lenient().when(request.getHeader(ExternalHeaders.X_INVOICE_ID)).thenReturn(null);
    }

    @Test
    void shouldNormalizeWoodyHeadersFromLowercase() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                WOODY_TRACE_ID, WOODY_SPAN_ID, WOODY_PARENT_ID, WOODY_DEADLINE
        )));
        when(request.getHeader(WOODY_TRACE_ID)).thenReturn("trace-123");
        when(request.getHeader(WOODY_SPAN_ID)).thenReturn("span-456");
        when(request.getHeader(WOODY_PARENT_ID)).thenReturn("parent-789");
        when(request.getHeader(WOODY_DEADLINE)).thenReturn("2030-01-01T00:00:00Z");

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("trace-123", normalized.get(WOODY_TRACE_ID));
        assertEquals("span-456", normalized.get(WOODY_SPAN_ID));
        assertEquals("parent-789", normalized.get(WOODY_PARENT_ID));
        assertEquals("2030-01-01T00:00:00Z", normalized.get(WOODY_DEADLINE));
    }

    @Test
    void shouldNormalizeXWoodyHeadersToWoody() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                ExternalHeaders.X_WOODY_TRACE_ID, ExternalHeaders.X_WOODY_SPAN_ID, ExternalHeaders.X_WOODY_PARENT_ID
        )));
        when(request.getHeader(ExternalHeaders.X_WOODY_TRACE_ID)).thenReturn("trace-123");
        when(request.getHeader(ExternalHeaders.X_WOODY_SPAN_ID)).thenReturn("span-456");
        when(request.getHeader(ExternalHeaders.X_WOODY_PARENT_ID)).thenReturn("parent-789");

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("trace-123", normalized.get(WOODY_TRACE_ID));
        assertEquals("span-456", normalized.get(WOODY_SPAN_ID));
        assertEquals("parent-789", normalized.get(WOODY_PARENT_ID));
    }

    @Test
    void shouldNormalizeUserIdentityMetadataFromXWoody() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                ExternalHeaders.X_WOODY_META_ID,
                ExternalHeaders.X_WOODY_META_USERNAME,
                ExternalHeaders.X_WOODY_META_EMAIL,
                ExternalHeaders.X_WOODY_META_REALM
        )));
        when(request.getHeader(ExternalHeaders.X_WOODY_META_ID)).thenReturn("user-id-123");
        when(request.getHeader(ExternalHeaders.X_WOODY_META_USERNAME)).thenReturn("john.doe");
        when(request.getHeader(ExternalHeaders.X_WOODY_META_EMAIL)).thenReturn("john@example.com");
        when(request.getHeader(ExternalHeaders.X_WOODY_META_REALM)).thenReturn("/internal");

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("user-id-123", normalized.get(WOODY_META_ID));
        assertEquals("john.doe", normalized.get(WOODY_META_USERNAME));
        assertEquals("john@example.com", normalized.get(WOODY_META_EMAIL));
        assertEquals("/internal", normalized.get(WOODY_META_REALM));
    }

    @Test
    void shouldNormalizeTraceparentHeader() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(OTEL_TRACE_PARENT)));
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn("00-123abc-456def-01");

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("00-123abc-456def-01", normalized.get(OTEL_TRACE_PARENT));
    }

    @Test
    void shouldMergeJwtMetadataIntoHeaders() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        try (MockedStatic<JwtTokenDetailsExtractor> extractor = mockStatic(JwtTokenDetailsExtractor.class)) {
            var tokenDetails = new JwtTokenDetails(
                    "user-jwt-id",
                    "jwt-username",
                    "jwt@email.com",
                    "/jwt-realm",
                    List.of("ROLE_USER")
            );
            extractor.when(() -> JwtTokenDetailsExtractor.extractFromContext(authentication))
                    .thenReturn(Optional.of(tokenDetails));

            var normalized = TraceContextHeadersNormalizer.normalize(request);

            assertEquals("user-jwt-id", normalized.get(WOODY_META_ID));
            assertEquals("jwt-username", normalized.get(WOODY_META_USERNAME));
            assertEquals("jwt@email.com", normalized.get(WOODY_META_EMAIL));
            assertEquals("/jwt-realm", normalized.get(WOODY_META_REALM));
        }
    }

    @Test
    void shouldMergeJwtMetadataWithHeaders() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                ExternalHeaders.X_WOODY_META_ID
        )));
        when(request.getHeader(ExternalHeaders.X_WOODY_META_ID)).thenReturn("header-user-id");
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        try (MockedStatic<JwtTokenDetailsExtractor> extractor = mockStatic(JwtTokenDetailsExtractor.class)) {
            var tokenDetails = new JwtTokenDetails(
                    "jwt-user-id",
                    "jwt-username",
                    null,
                    null,
                    List.of()
            );
            extractor.when(() -> JwtTokenDetailsExtractor.extractFromContext(authentication))
                    .thenReturn(Optional.of(tokenDetails));

            var normalized = TraceContextHeadersNormalizer.normalize(request);

            assertEquals("jwt-user-id", normalized.get(WOODY_META_ID));
            assertEquals("jwt-username", normalized.get(WOODY_META_USERNAME));
        }
    }

    @Test
    void shouldMergeRequestDeadlineToWoodyDeadline() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn("2030-12-31T23:59:59Z");
        when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn(null);
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("2030-12-31T23:59:59Z", normalized.get(WOODY_DEADLINE));
        assertEquals("2030-12-31T23:59:59Z", normalized.get(WOODY_META_REQUEST_DEADLINE));
        assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_DEADLINE));
    }

    @Test
    void shouldMergeRelativeDeadline() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn("30s");
        when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn("req-123");
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertNotNull(normalized.get(WOODY_DEADLINE));
        assertEquals(normalized.get(WOODY_DEADLINE), normalized.get(WOODY_META_REQUEST_DEADLINE));
        assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_DEADLINE));
        assertTrue(Instant.parse(normalized.get(WOODY_DEADLINE)).isAfter(Instant.now()));
    }

    @Test
    void shouldNotOverwriteExistingWoodyDeadline() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(WOODY_DEADLINE)));
        when(request.getHeader(WOODY_DEADLINE)).thenReturn("2025-01-01T00:00:00Z");
        when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn("2030-12-31T23:59:59Z");
        when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn(null);
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("2025-01-01T00:00:00Z", normalized.get(WOODY_DEADLINE));
        assertEquals("2030-12-31T23:59:59Z", normalized.get(WOODY_META_REQUEST_DEADLINE));
        assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_DEADLINE));
    }

    @Test
    void shouldPreserveRequestIdWithoutDeadline() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));
        when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn("req-no-deadline");
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(null);
        when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn(null);

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertEquals("req-no-deadline", normalized.get(WOODY_META_REQUEST_ID));
        assertFalse(normalized.containsKey(WOODY_META_REQUEST_DEADLINE));
        assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_ID));
    }

    @Test
    void shouldHandleEmptyHeaders() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertTrue(normalized.isEmpty());
    }

    @Test
    void shouldHandleNullHeaderEnumeration() {
        when(request.getHeaderNames()).thenReturn(null);

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertTrue(normalized.isEmpty());
    }

    @Test
    void shouldIgnoreJwtMetadataWhenAuthenticationMissing() {
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(Collections.emptyList()));

        final var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertTrue(normalized.isEmpty());
    }

    @Test
    void shouldIgnoreNullHeaderValues() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                WOODY_TRACE_ID, WOODY_SPAN_ID
        )));
        when(request.getHeader(WOODY_TRACE_ID)).thenReturn(null);
        when(request.getHeader(WOODY_SPAN_ID)).thenReturn("span-456");

        var normalized = TraceContextHeadersNormalizer.normalize(request);

        assertFalse(normalized.containsKey(WOODY_TRACE_ID));
        assertEquals("span-456", normalized.get(WOODY_SPAN_ID));
    }

    @Test
    void shouldHandleComplexScenarioWithAllHeaderTypes() {
        when(request.getHeaderNames()).thenReturn(Collections.enumeration(List.of(
                WOODY_TRACE_ID,
                ExternalHeaders.X_WOODY_SPAN_ID,
                ExternalHeaders.X_WOODY_PARENT_ID,
                ExternalHeaders.X_WOODY_META_EMAIL,
                OTEL_TRACE_PARENT,
                "content-type",
                "authorization"
        )));
        when(request.getHeader(WOODY_TRACE_ID)).thenReturn("GZyWNGugAAA");
        when(request.getHeader(ExternalHeaders.X_WOODY_SPAN_ID)).thenReturn("GZyWNGugBBB");
        when(request.getHeader(ExternalHeaders.X_WOODY_PARENT_ID)).thenReturn("undefined");
        when(request.getHeader(ExternalHeaders.X_WOODY_META_EMAIL)).thenReturn("noreply@valitydev.com");
        when(request.getHeader(OTEL_TRACE_PARENT)).thenReturn(
                "00-cfa3d3072a4e3e99fc14829a65311819-6e4609576fa4d077-01");
        when(request.getHeader(ExternalHeaders.X_REQUEST_ID)).thenReturn("req-complex");
        when(request.getHeader(ExternalHeaders.X_REQUEST_DEADLINE)).thenReturn("2030-01-01T00:00:00Z");

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        try (MockedStatic<JwtTokenDetailsExtractor> extractor = mockStatic(JwtTokenDetailsExtractor.class)) {
            var tokenDetails = new JwtTokenDetails(
                    "b54a93c4-415d-4f33-a5e9-3608fd043ff4",
                    "noreply@valitydev.com",
                    "noreply@valitydev.com",
                    "/internal",
                    List.of("ROLE_USER")
            );
            extractor.when(() -> JwtTokenDetailsExtractor.extractFromContext(authentication))
                    .thenReturn(Optional.of(tokenDetails));

            var normalized = TraceContextHeadersNormalizer.normalize(request);

            assertEquals("GZyWNGugAAA", normalized.get(WOODY_TRACE_ID));
            assertEquals("GZyWNGugBBB", normalized.get(WOODY_SPAN_ID));
            assertEquals("undefined", normalized.get(WOODY_PARENT_ID));
            assertEquals("noreply@valitydev.com", normalized.get(WOODY_META_EMAIL));
            assertEquals("b54a93c4-415d-4f33-a5e9-3608fd043ff4",
                    normalized.get(WOODY_META_ID));
            assertEquals("noreply@valitydev.com", normalized.get(WOODY_META_USERNAME));
            assertEquals("/internal", normalized.get(WOODY_META_REALM));
            assertEquals("00-cfa3d3072a4e3e99fc14829a65311819-6e4609576fa4d077-01", normalized.get(OTEL_TRACE_PARENT));
            assertEquals("2030-01-01T00:00:00Z", normalized.get(WOODY_DEADLINE));
            assertEquals("req-complex", normalized.get(WOODY_META_REQUEST_ID));
            assertEquals("2030-01-01T00:00:00Z", normalized.get(WOODY_META_REQUEST_DEADLINE));
            assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_ID));
            assertFalse(normalized.containsKey(ExternalHeaders.X_REQUEST_DEADLINE));
        }
    }

    @Test
    void shouldNormalizeResponseHeaders() {
        var responseHeaders = new HttpHeaders();
        responseHeaders.add(WOODY_TRACE_ID, "resp-trace");
        responseHeaders.add(WOODY_SPAN_ID, "resp-span");
        responseHeaders.add(WOODY_PARENT_ID, "resp-parent");
        responseHeaders.add(WOODY_META_ID, "resp-user");
        responseHeaders.add(WOODY_META_REQUEST_ID, "resp-req");
        responseHeaders.add(WOODY_META_REQUEST_DEADLINE, "2030-01-01T00:00:00Z");
        responseHeaders.add(WOODY_META_REQUEST_INVOICE_ID, "resp-req");
        responseHeaders.add(WOODY_DEADLINE, "2030-01-01T00:00:00Z");
        responseHeaders.add(WOODY_ERROR_CLASS, "resp-req");
        responseHeaders.add(WOODY_ERROR_REASON, "resp-req");
        responseHeaders.add(OTEL_TRACE_PARENT, "00-abc-def-01");
        responseHeaders.add(OTEL_TRACE_STATE, "00-abc-def-01");
        responseHeaders.add("Content-Type", "application/json");
        responseHeaders.add("Cache-Control", "no-cache");

        var normalized = TraceContextHeadersNormalizer.normalizeResponseHeaders(responseHeaders);

        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_TRACE_ID));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_SPAN_ID));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_PARENT_ID));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_DEADLINE));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_ERROR_CLASS));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_ERROR_REASON));
        assertTrue(normalized.containsKey(ExternalHeaders.X_WOODY_META_ID));
        assertTrue(normalized.containsKey(ExternalHeaders.X_REQUEST_ID));
        assertTrue(normalized.containsKey(ExternalHeaders.X_REQUEST_DEADLINE));
        assertTrue(normalized.containsKey(ExternalHeaders.X_INVOICE_ID));
        assertTrue(normalized.containsKey(OTEL_TRACE_PARENT));
        assertTrue(normalized.containsKey(OTEL_TRACE_STATE));
        assertFalse(normalized.containsKey("Content-Type"));
        assertFalse(normalized.containsKey("Cache-Control"));
    }
}
