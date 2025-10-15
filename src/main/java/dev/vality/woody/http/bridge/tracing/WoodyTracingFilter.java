package dev.vality.woody.http.bridge.tracing;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.flow.error.WRuntimeException;
import dev.vality.woody.http.bridge.properties.TracingProperties;
import dev.vality.woody.http.bridge.service.SecretService;
import dev.vality.woody.http.bridge.token.CipherTokenExtractor;
import dev.vality.woody.http.bridge.token.TokenCipher;
import dev.vality.woody.http.bridge.token.TokenPayload;
import dev.vality.woody.http.bridge.token.VaultTokenKeyExtractor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriUtils;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.vality.woody.http.bridge.properties.TracingProperties.TracePolicy;

@Slf4j
@RequiredArgsConstructor
public final class WoodyTracingFilter extends OncePerRequestFilter {

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            HttpHeaders.AUTHORIZATION.toLowerCase(Locale.ROOT),
            HttpHeaders.COOKIE.toLowerCase(Locale.ROOT),
            HttpHeaders.SET_COOKIE.toLowerCase(Locale.ROOT)
    );

    public static final String CIPHER_TOKEN_ATTRIBUTE = "decryptedCipherTokenPayload";
    public static final String VAULT_TOKEN_ATTRIBUTE = "decryptedVaultTokenPayload";

    private final TracingProperties tracingProperties;
    private final WoodyTraceResponseHandler woodyTraceResponseHandler;
    private final TokenCipher tokenCipher;
    private final @Nullable SecretService secretService;
    private final CipherTokenExtractor cipherTokenExtractor;
    private final VaultTokenKeyExtractor vaultTokenKeyExtractor;

    @Override
    @SneakyThrows
    @SuppressWarnings("NullableProblems")
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        var path = getRequestPath(request);
        var port = request.getLocalPort();
        var policy = tracingProperties.resolvePolicy(port, path);
        if (policy == null) {
            filterChain.doFilter(request, response);
            return;
        }
        switch (policy.requestHeaderMode()) {
            case OFF -> handleWithoutTraceRestore(request, response, filterChain, policy);
            case WOODY_OR_X_WOODY -> handleWithTraceRestore(request, response, filterChain, policy);
            case CIPHER_TOKEN -> handleCipherToken(request, response, filterChain, policy);
            case VAULT_TOKEN -> handleVaultToken(request, response, filterChain, policy);
            default -> filterChain.doFilter(request, response);
        }
    }

    private void handleWithoutTraceRestore(HttpServletRequest request,
                                           HttpServletResponse response,
                                           FilterChain filterChain,
                                           TracePolicy policy) {
        new WFlow().createServiceFork(() -> {
            logReceived(request);
            doFilterWithTraceHandling(request, response, filterChain, policy);
            logSent(request, response);
        }).run();
    }

    private void handleWithTraceRestore(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain filterChain,
                                        TracePolicy policy) {
        var normalized = TraceContextHeadersNormalizer.normalize(request);
        var headersForTrace = TraceContextHeadersValidation.validate(normalized);
        var restoredTraceData = TraceContextRestorer.restoreTraceData(headersForTrace);
        WFlow.create(() -> {
            logReceived(request);
            doFilterWithTraceHandling(request, response, filterChain, policy);
            logSent(request, response);
        }, restoredTraceData).run();
    }

    private void handleCipherToken(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain,
                                   TracePolicy policy) {
        var requestPath = getRequestPath(request);
        var resolvedToken = cipherTokenExtractor.extractToken(request);
        if (resolvedToken == null || resolvedToken.isBlank()) {
            respondForbidden(response, requestPath, "Empty cipher token");
            return;
        }
        final String decodedToken;
        try {
            decodedToken = UriUtils.decode(resolvedToken, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException decodeError) {
            respondForbidden(response, requestPath, "Failed to decode cipher token");
            return;
        }
        var payload = decryptAndValidate(decodedToken, requestPath, policy);
        if (payload == null) {
            respondForbidden(response, requestPath, "Invalid cipher token payload");
            return;
        }
        proceedWithTokenPayload(request, response, filterChain, policy, payload, CIPHER_TOKEN_ATTRIBUTE);
    }

    private void handleVaultToken(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain,
                                  TracePolicy policy) {
        var requestPath = getRequestPath(request);
        if (secretService == null) {
            respondForbidden(response, requestPath, "Vault token support is not configured");
            return;
        }
        var tokenKey = vaultTokenKeyExtractor.extractTokenKey(request);
        if (tokenKey == null || tokenKey.isBlank()) {
            respondForbidden(response, requestPath, "Empty vault token key");
            return;
        }
        final TokenPayload token;
        try {
            token = secretService.getVaultToken(tokenKey);
        } catch (Throwable ex) {
            respondForbidden(response, requestPath, "Vault token unavailable");
            return;
        }
        if (token == null || isExpired(token.timestamp(), policy.tokenTtl())) {
            respondForbidden(response, requestPath, "Invalid cipher token payload");
            return;
        }
        proceedWithTokenPayload(request, response, filterChain, policy, token, VAULT_TOKEN_ATTRIBUTE);
    }

    private void proceedWithTokenPayload(HttpServletRequest request,
                                         HttpServletResponse response,
                                         FilterChain filterChain,
                                         TracePolicy policy,
                                         TokenPayload payload,
                                         String attributeName) {
        request.setAttribute(attributeName, payload);
        var restoredTraceData = TraceContextRestorer.restoreTraceData(payload);
        WFlow.create(() -> {
            logReceived(request);
            doFilterWithTraceHandling(request, response, filterChain, policy);
            logSent(request, response);
        }, restoredTraceData).run();
    }

    @SneakyThrows
    private void doFilterWithTraceHandling(HttpServletRequest request,
                                           HttpServletResponse response,
                                           FilterChain filterChain,
                                           TracePolicy policy) {
        try {
            filterChain.doFilter(request, response);
            woodyTraceResponseHandler.handleSuccess(response, policy.responseHeaderMode());
        } catch (WRuntimeException woodyError) {
            log.warn("Handled Woody exception during request processing", woodyError);
            if (policy.propagateErrors()) {
                woodyTraceResponseHandler.recordOtelSpanException(woodyError);
                throw woodyError;
            }
            woodyTraceResponseHandler.handleWoodyException(response, woodyError, policy.responseHeaderMode());
        } catch (Throwable unexpected) {
            log.error("Unhandled exception during request processing", unexpected);
            if (policy.propagateErrors()) {
                woodyTraceResponseHandler.recordOtelSpanException(unexpected);
                throw unexpected;
            }
            woodyTraceResponseHandler.handleUnexpectedError(response, unexpected, policy.responseHeaderMode());
        }
    }

    private void logReceived(HttpServletRequest request) {
        log.info("-> Received {} {} | params: {}, headers: {}", request.getMethod(), getRequestPath(request),
                extractParams(request), sanitizeHeaders(request));
    }

    private void logSent(HttpServletRequest request, HttpServletResponse response) {
        log.info("<- Sent {} {} | status: {}, headers: {}", request.getMethod(), getRequestPath(request),
                response.getStatus(), sanitizeResponseHeaders(response));
    }

    private TokenPayload decryptAndValidate(String token, String requestPath, TracePolicy policy) {
        if (tokenCipher == null) {
            log.warn("Decrypt attempt skipped due to misconfiguration for {}", requestPath);
            return null;
        }
        var secretKey = resolveCipherSecretKey(policy);
        if (secretKey == null || secretKey.isBlank()) {
            log.warn("Cipher token secret key is not configured for {}", requestPath);
            return null;
        }
        final TokenPayload payload;
        try {
            payload = tokenCipher.decrypt(token, secretKey);
        } catch (Throwable ex) {
            log.warn("Failed to decrypt tracing token {}", token, ex);
            return null;
        }
        if (isExpired(payload.timestamp(), policy.tokenTtl())) {
            log.warn("Tracing token expired for payload {}", payload);
            return null;
        }
        return payload;
    }

    private String resolveCipherSecretKey(TracePolicy policy) {
        var inlineSecret = policy.defaultCipherToken();
        if (inlineSecret != null && !inlineSecret.isBlank()) {
            return inlineSecret;
        }
        if (secretService != null) {
            return secretService.getCipherTokenSecretKey();
        }
        return null;
    }

    private boolean isExpired(LocalDateTime issuedAt, Duration ttl) {
        if (issuedAt == null || ttl == null || ttl.isNegative() || ttl.isZero()) {
            return false;
        }
        var now = LocalDateTime.now(ZoneOffset.UTC);
        return issuedAt.plus(ttl).isBefore(now);
    }

    @SneakyThrows
    private void respondForbidden(HttpServletResponse response,
                                  String requestPath,
                                  String reason) {
        var status = HttpServletResponse.SC_FORBIDDEN;
        log.warn("<- Sent [{} {}]: {}", status, requestPath, reason);
        response.sendError(status, "Invalid token");
    }

    public static String extractParams(HttpServletRequest servletRequest) {
        return servletRequest.getParameterMap().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + String.join(",", entry.getValue()))
                .collect(Collectors.joining(", "));
    }

    private static HttpHeaders sanitizeHeaders(HttpServletRequest request) {
        var headers = new HttpHeaders();
        var collectedHeaders = collectHeaders(request);
        collectedHeaders.forEach((name, value) -> {
            if (isSensitive(name)) {
                headers.add(name, "***");
            } else {
                headers.add(name, value);
            }
        });
        return headers;
    }

    private static Map<String, String> collectHeaders(HttpServletRequest request) {
        var headers = new LinkedHashMap<String, String>();
        var headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                var name = headerNames.nextElement();
                var value = request.getHeader(name);
                if (value != null) {
                    headers.put(name, value);
                }
            }
        }
        return headers;
    }

    private static boolean isSensitive(String headerName) {
        return SENSITIVE_HEADERS.contains(headerName.toLowerCase(Locale.ROOT));
    }

    private static HttpHeaders sanitizeResponseHeaders(HttpServletResponse response) {
        var headers = new HttpHeaders();
        response.getHeaderNames().forEach(name -> {
            if (isSensitive(name)) {
                headers.add(name, "***");
            } else {
                response.getHeaders(name).forEach(value -> headers.add(name, value));
            }
        });
        return headers;
    }

    public static String getRequestPath(HttpServletRequest request) {
        var servletPath = request.getServletPath();
        if (servletPath != null && !servletPath.isBlank()) {
            return servletPath;
        }
        var requestPath = request.getRequestURI();
        if (requestPath != null && !requestPath.isBlank()) {
            return requestPath;
        }
        return "";
    }
}
