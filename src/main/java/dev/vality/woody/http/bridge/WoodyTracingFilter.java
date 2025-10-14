package dev.vality.woody.http.bridge;

import dev.vality.woody.api.flow.WFlow;
import dev.vality.woody.api.flow.error.WRuntimeException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static dev.vality.woody.http.bridge.TracingProperties.*;

@Slf4j
@RequiredArgsConstructor
public final class WoodyTracingFilter extends OncePerRequestFilter {

    private static final Set<String> SENSITIVE_HEADERS = Set.of(
            HttpHeaders.AUTHORIZATION.toLowerCase(Locale.ROOT),
            HttpHeaders.COOKIE.toLowerCase(Locale.ROOT),
            HttpHeaders.SET_COOKIE.toLowerCase(Locale.ROOT)
    );

    private final TracingProperties tracingProperties;
    private final WoodyTraceResponseHandler woodyTraceResponseHandler;

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

    private static String getRequestPath(HttpServletRequest request) {
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
