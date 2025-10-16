package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.flow.error.WErrorDefinition;
import dev.vality.woody.api.flow.error.WErrorSource;
import dev.vality.woody.api.flow.error.WErrorType;
import dev.vality.woody.api.flow.error.WRuntimeException;
import dev.vality.woody.api.trace.context.TraceContext;
import dev.vality.woody.http.bridge.exceptions.WoodyHttpBridgeException;
import dev.vality.woody.http.bridge.properties.TracingProperties;
import dev.vality.woody.http.bridge.properties.TracingProperties.Endpoint;
import dev.vality.woody.http.bridge.properties.TracingProperties.RequestHeaderMode;
import dev.vality.woody.http.bridge.properties.TracingProperties.ResponseHeaderMode;
import dev.vality.woody.http.bridge.service.SecretService;
import dev.vality.woody.http.bridge.token.CipherTokenExtractor;
import dev.vality.woody.http.bridge.token.TokenCipher;
import dev.vality.woody.http.bridge.token.TokenPayload;
import dev.vality.woody.http.bridge.token.VaultTokenKeyExtractor;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.ExternalHeaders.*;
import static dev.vality.woody.http.bridge.tracing.TraceHeadersConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WoodyTracingFilterTest {

    private SdkTracerProvider tracerProvider;
    private WoodyTracingFilter filter;
    private TracingProperties tracingProperties;
    private TokenCipher tokenCipher;
    private SecretService secretService;
    private CipherTokenExtractor cipherTokenExtractor;
    private VaultTokenKeyExtractor vaultTokenKeyExtractor;

    @BeforeEach
    void setUp() {
        GlobalOpenTelemetry.resetForTest();
        tracerProvider = SdkTracerProvider.builder().build();
        final var openTelemetry = OpenTelemetrySdk.builder()
                .setTracerProvider(tracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .build();
        GlobalOpenTelemetry.set(openTelemetry);
        tracingProperties = new TracingProperties();
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.OFF, null);
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
    void shouldHandleCipherTokenSuccessfully() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        var endpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseThrow();
        endpoint.setTokenTtl("15");
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/tokenValue");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        var payload = new TokenPayload(
                "https://example.com",
                java.time.LocalDateTime.now(java.time.ZoneOffset.UTC),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                "congo=4"
        );

        when(cipherTokenExtractor.extractToken(request)).thenReturn("tokenValue");
        when(secretService.getCipherTokenSecretKey(any())).thenReturn("secret");
        when(tokenCipher.decrypt("tokenValue", "secret")).thenReturn(payload);

        var chainInvoked = new java.util.concurrent.atomic.AtomicBoolean(false);
        filter.doFilter(request, response, (req, res) -> chainInvoked.set(true));

        assertTrue(chainInvoked.get());
        assertEquals(payload, request.getAttribute(WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE));
        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldRejectCipherTokenWhenExpired() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        var endpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseThrow();
        endpoint.setTokenTtl("1");
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/tokenValue");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        var payload = new TokenPayload(
                "https://example.com",
                java.time.LocalDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(10),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                null
        );

        when(cipherTokenExtractor.extractToken(request)).thenReturn("tokenValue");
        when(secretService.getCipherTokenSecretKey(any())).thenReturn("secret");
        when(tokenCipher.decrypt("tokenValue", "secret")).thenReturn(payload);

        var chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(request.getAttribute(WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectCipherTokenWhenDecryptFails() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/tokenValue");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        when(cipherTokenExtractor.extractToken(request)).thenReturn("tokenValue");
        when(secretService.getCipherTokenSecretKey(any())).thenReturn("secret");
        when(tokenCipher.decrypt("tokenValue", "secret")).thenThrow(new IllegalArgumentException("boom"));

        var chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(request.getAttribute(WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectCipherTokenWhenBlank() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        when(cipherTokenExtractor.extractToken(request)).thenReturn(" ");

        var chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(request.getAttribute(WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE));
        verifyNoInteractions(tokenCipher, secretService);
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldUseInlineCipherSecretWhenConfigured() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        var endpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseThrow();
        endpoint.setDefaultCipherToken("inline-secret");
        endpoint.setTokenTtl("30");
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/tokenValue");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();
        var payload = new TokenPayload(
                "https://example.com",
                java.time.LocalDateTime.now(java.time.ZoneOffset.UTC),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                null
        );

        when(cipherTokenExtractor.extractToken(request)).thenReturn("tokenValue");
        when(secretService.getCipherTokenSecretKey(any())).thenAnswer(invocation -> {
            var policy = invocation.getArgument(0, TracingProperties.TracePolicy.class);
            return policy.defaultCipherToken();
        });
        when(tokenCipher.decrypt("tokenValue", "inline-secret")).thenReturn(payload);

        var chainInvoked = new java.util.concurrent.atomic.AtomicBoolean(false);
        filter.doFilter(request, response, (req, res) -> chainInvoked.set(true));

        assertTrue(chainInvoked.get());
        assertEquals(payload, request.getAttribute(WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE));
        assertEquals(200, response.getStatus());
        verify(secretService).getCipherTokenSecretKey(any());
    }

    @Test
    void shouldHandleVaultTokenSuccessfully() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.VAULT_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        var endpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseThrow();
        endpoint.setTokenTtl("15");
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/vaultKey");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        var payload = new TokenPayload(
                "https://example.com",
                java.time.LocalDateTime.now(java.time.ZoneOffset.UTC),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                null
        );

        when(vaultTokenKeyExtractor.extractTokenKey(request)).thenReturn("vaultKey");
        when(secretService.getVaultToken("vaultKey")).thenReturn(payload);

        var chainInvoked = new java.util.concurrent.atomic.AtomicBoolean(false);
        filter.doFilter(request, response, (req, res) -> chainInvoked.set(true));

        assertTrue(chainInvoked.get());
        assertEquals(payload, request.getAttribute(WoodyTracingFilter.VAULT_TOKEN_ATTRIBUTE));
        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldRejectVaultTokenWhenExpired() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.VAULT_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        var endpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseThrow();
        endpoint.setTokenTtl("1");
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/vaultKey");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        var payload = new TokenPayload(
                "https://example.com",
                java.time.LocalDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(5),
                "invoice-1",
                "11111111111111111111111111111111",
                "2222222222222222",
                "3333333333333333",
                "00-11111111111111111111111111111111-2222222222222222-01",
                null
        );

        when(vaultTokenKeyExtractor.extractTokenKey(request)).thenReturn("vaultKey");
        when(secretService.getVaultToken("vaultKey")).thenReturn(payload);

        var chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(request.getAttribute(WoodyTracingFilter.VAULT_TOKEN_ATTRIBUTE));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectVaultTokenWhenUnavailable() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.VAULT_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/vaultKey");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        when(vaultTokenKeyExtractor.extractTokenKey(request)).thenReturn("vaultKey");
        when(secretService.getVaultToken("vaultKey")).thenThrow(new IllegalStateException("vault down"));

        assertThrows(WoodyHttpBridgeException.class,
                () -> filter.doFilter(request, response, mock(FilterChain.class)));
    }

    @Test
    void shouldRejectVaultTokenWhenKeyBlank() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = mock(SecretService.class);
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.VAULT_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        when(vaultTokenKeyExtractor.extractTokenKey(request)).thenReturn(" ");

        var chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);

        assertEquals(403, response.getStatus());
        assertNull(request.getAttribute(WoodyTracingFilter.VAULT_TOKEN_ATTRIBUTE));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void shouldRejectVaultTokenWhenSecretServiceMissing() throws Exception {
        tokenCipher = mock(TokenCipher.class);
        secretService = null;
        cipherTokenExtractor = mock(CipherTokenExtractor.class);
        vaultTokenKeyExtractor = mock(VaultTokenKeyExtractor.class);
        configureFilter(RequestHeaderMode.VAULT_TOKEN_EXPERIMENTAL, ResponseHeaderMode.OFF, null);
        rebuildFilter();

        var request = new MockHttpServletRequest("GET", "/wachter/vaultKey");
        request.setLocalPort(8080);
        final var response = new MockHttpServletResponse();

        assertThrows(WoodyHttpBridgeException.class,
                () -> filter.doFilter(request, response, mock(FilterChain.class)));
    }

    @Test
    void shouldInitializeTraceContext() throws Exception {
        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "test-trace");
        request.addHeader(X_WOODY_SPAN_ID, "test-span");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldHandleRequestCorrectly() throws Exception {
        final var request = new MockHttpServletRequest("GET", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldSetSpanStatusErrorForServerError() throws Exception {
        final var request = new MockHttpServletRequest("GET", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        final FilterChain chain = (req, res) -> ((MockHttpServletResponse) res).setStatus(503);

        filter.doFilter(request, response, chain);

        assertEquals(503, response.getStatus());
    }

    @Test
    void shouldEchoWoodyHeadersOnSuccess() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.WOODY, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "woody-trace-id");
        request.addHeader(X_WOODY_SPAN_ID, "woody-span-id");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("woody-trace-id", response.getHeader(WOODY_TRACE_ID));
        assertEquals("woody-span-id", response.getHeader(WOODY_SPAN_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_SPAN_ID));
    }

    @Test
    void shouldReturnXWoodyHeadersWhenConfigured() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.X_WOODY, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "x-woody-trace");
        request.addHeader(X_WOODY_SPAN_ID, "x-woody-span");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("x-woody-trace", response.getHeader(X_WOODY_TRACE_ID));
        assertEquals("x-woody-span", response.getHeader(X_WOODY_SPAN_ID));
        assertNull(response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(WOODY_SPAN_ID));
    }

    @Test
    void shouldMapWoodyExceptionToErrorResponse() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.WOODY, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "trace-err");
        request.addHeader(X_WOODY_SPAN_ID, "span-err");

        var errorDefinition = new WErrorDefinition(WErrorSource.INTERNAL);
        errorDefinition.setErrorType(WErrorType.UNEXPECTED_ERROR);
        errorDefinition.setErrorReason("boom");

        filter.doFilter(request, response, (req, res) -> {
            throw new WRuntimeException(errorDefinition);
        });

        assertEquals(500, response.getStatus());
        assertEquals(WErrorType.UNEXPECTED_ERROR.getKey(), response.getHeader(WOODY_ERROR_CLASS));
        assertEquals("boom", response.getHeader(WOODY_ERROR_REASON));
        assertNull(response.getHeader(X_WOODY_ERROR_CLASS));
        assertNull(response.getHeader(X_WOODY_ERROR_REASON));
    }

    @Test
    void shouldFallbackToLightweightModeWhenDisabled() throws Exception {
        configureFilter(RequestHeaderMode.OFF, ResponseHeaderMode.OFF, null);

        final var request = new MockHttpServletRequest("GET", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);

        filter.doFilter(request, response, new MockFilterChain());

        assertNull(response.getHeader(WOODY_TRACE_ID));
    }

    @Test
    void shouldApplyCustomEndpointConfiguration() throws Exception {
        tracingProperties.getEndpoints().clear();
        var endpoint = new Endpoint();
        endpoint.setPort(8080);
        endpoint.setPath("/custom");
        endpoint.setRequestHeaderMode(RequestHeaderMode.WOODY_OR_X_WOODY);
        endpoint.setResponseHeaderMode(ResponseHeaderMode.WOODY);
        tracingProperties.getEndpoints().add(endpoint);
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.WOODY, null);

        final var request = new MockHttpServletRequest("POST", "/custom");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "custom-trace");
        request.addHeader(X_WOODY_SPAN_ID, "custom-span");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("custom-trace", response.getHeader(WOODY_TRACE_ID));
    }

    @Test
    void shouldSkipWhenEndpointDoesNotMatchConfiguration() throws Exception {
        tracingProperties.getEndpoints().clear();
        var endpoint = new Endpoint();
        endpoint.setPort(9090);
        endpoint.setPath("/other");
        endpoint.setRequestHeaderMode(RequestHeaderMode.WOODY_OR_X_WOODY);
        endpoint.setResponseHeaderMode(ResponseHeaderMode.OFF);
        tracingProperties.getEndpoints().add(endpoint);
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.OFF, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "trace-skip");
        request.addHeader(X_WOODY_SPAN_ID, "span-skip");

        filter.doFilter(request, response, new MockFilterChain());

        assertNull(response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
    }

    @Test
    void shouldRespectWoodyModeExplicitly() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.WOODY, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "woody-trace-only");
        request.addHeader(X_WOODY_SPAN_ID, "woody-span-only");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("woody-trace-only", response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
    }

    @Test
    void shouldExposeHttpHeadersWhenConfigured() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.HTTP, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "trace-http");
        request.addHeader(X_WOODY_SPAN_ID, "span-http");
        request.addHeader(OTEL_TRACE_PARENT, "00-11111111111111111111111111111111-2222222222222222-01");
        request.addHeader(X_REQUEST_ID, "request-123");
        request.addHeader(X_REQUEST_DEADLINE, "2025-10-14T06:00:00Z");

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("00-11111111111111111111111111111111-2222222222222222-01",
                response.getHeader(OTEL_TRACE_PARENT));
        assertEquals("request-123", response.getHeader(X_REQUEST_ID));
        assertEquals("2025-10-14T06:00:00Z", response.getHeader(X_REQUEST_DEADLINE));
        assertNull(response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
    }

    @Test
    void shouldExposeHttpErrorsWhenConfigured() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.HTTP, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "trace-err");
        request.addHeader(X_WOODY_SPAN_ID, "span-err");

        var errorDefinition = new WErrorDefinition(WErrorSource.INTERNAL);
        errorDefinition.setErrorType(WErrorType.UNEXPECTED_ERROR);
        errorDefinition.setErrorReason("http-boom");

        filter.doFilter(request, response, (req, res) -> {
            throw new WRuntimeException(errorDefinition);
        });

        assertEquals(500, response.getStatus());
        assertEquals(WErrorType.UNEXPECTED_ERROR.getKey(), response.getHeader(X_ERROR_CLASS));
        assertEquals("http-boom", response.getHeader(X_ERROR_REASON));
        assertNull(response.getHeader(WOODY_ERROR_CLASS));
        assertNull(response.getHeader(WOODY_ERROR_REASON));
    }

    @Test
    void shouldReturnNoHeadersWhenOffMode() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.OFF, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);
        request.addHeader(X_WOODY_TRACE_ID, "trace-off");
        request.addHeader(X_WOODY_SPAN_ID, "span-off");

        filter.doFilter(request, response, new MockFilterChain());

        assertNull(response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
        assertNull(response.getHeader(OTEL_TRACE_PARENT));
    }

    @Test
    void shouldPropagateErrorsWhenOffModeByDefault() {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.OFF, null);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);

        var errorDefinition = new WErrorDefinition(WErrorSource.INTERNAL);
        errorDefinition.setErrorType(WErrorType.UNEXPECTED_ERROR);
        errorDefinition.setErrorReason("propagate");

        assertThrows(WRuntimeException.class, () -> filter.doFilter(request, response, (req, res) -> {
            throw new WRuntimeException(errorDefinition);
        }));
        assertEquals(200, response.getStatus());
    }

    @Test
    void shouldAllowDisablingErrorPropagationExplicitly() throws Exception {
        configureFilter(RequestHeaderMode.WOODY_OR_X_WOODY, ResponseHeaderMode.OFF, false);

        final var request = new MockHttpServletRequest("POST", "/wachter");
        final var response = new MockHttpServletResponse();
        request.setLocalPort(8080);

        var errorDefinition = new WErrorDefinition(WErrorSource.INTERNAL);
        errorDefinition.setErrorType(WErrorType.UNEXPECTED_ERROR);
        errorDefinition.setErrorReason("handled");

        filter.doFilter(request, response, (req, res) -> {
            throw new WRuntimeException(errorDefinition);
        });

        assertEquals(500, response.getStatus());
        assertNull(response.getHeader(WOODY_TRACE_ID));
        assertNull(response.getHeader(X_WOODY_TRACE_ID));
    }

    private void configureFilter(RequestHeaderMode requestHeaderMode,
                                 ResponseHeaderMode responseHeaderMode,
                                 Boolean propagateErrors) {
        var defaultEndpoint = tracingProperties.getEndpoints().stream()
                .filter(this::matchesDefault)
                .findFirst()
                .orElseGet(() -> {
                    var endpoint = defaultEndpoint();
                    tracingProperties.getEndpoints().add(endpoint);
                    return endpoint;
                });
        defaultEndpoint.setRequestHeaderMode(requestHeaderMode);
        defaultEndpoint.setResponseHeaderMode(responseHeaderMode);
        defaultEndpoint.setPropagateErrors(propagateErrors);
        rebuildFilter();
    }

    private Endpoint defaultEndpoint() {
        var endpoint = new Endpoint();
        endpoint.setPort(8080);
        endpoint.setPath("/wachter");
        return endpoint;
    }

    private boolean matchesDefault(Endpoint endpoint) {
        var portMatches = endpoint.getPort() == null || endpoint.getPort() == 8080;
        var pathMatches = endpoint.getPath() == null || endpoint.getPath().equals("/wachter");
        return portMatches && pathMatches;
    }

    private void rebuildFilter() {
        var lifecycleHandler = new WoodyTraceResponseHandler();
        filter = new WoodyTracingFilter(tracingProperties, lifecycleHandler, tokenCipher, secretService,
                cipherTokenExtractor, vaultTokenKeyExtractor);
    }
}
