package dev.vality.woody.http.bridge.properties;

import dev.vality.woody.http.bridge.token.TokenPayload;
import dev.vality.woody.http.bridge.tracing.WoodyTracingFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static dev.vality.woody.http.bridge.tracing.WoodyTracingFilter.getRequestPath;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "woody-http-bridge.tracing")
public class TracingProperties {

    private static final RequestHeaderMode DEFAULT_REQUEST_MODE = RequestHeaderMode.OFF;
    private static final ResponseHeaderMode DEFAULT_RESPONSE_MODE = ResponseHeaderMode.OFF;

    private List<Endpoint> endpoints = new ArrayList<>();

    @Getter
    @Setter
    public static class Endpoint {

        @NotNull
        private Integer port;
        @NotNull
        private String path;
        private RequestHeaderMode requestHeaderMode;
        private ResponseHeaderMode responseHeaderMode;
        private Boolean propagateErrors;
        private String defaultCipherToken;
        private String tokenTtl;

    }

    public enum RequestHeaderMode {
        OFF,
        WOODY_OR_X_WOODY,
        CIPHER_TOKEN_EXPERIMENTAL,
        VAULT_TOKEN_EXPERIMENTAL
    }

    public enum ResponseHeaderMode {
        OFF,
        WOODY,
        X_WOODY,
        HTTP
    }

    public TokenPayload extractTokenPayload(HttpServletRequest request) {
        return (TokenPayload) endpoints.stream()
                .filter(endpoint -> matches(endpoint, request.getLocalPort(), getRequestPath(request)))
                .findFirst()
                .map(endpoint -> switch (endpoint.requestHeaderMode) {
                    case CIPHER_TOKEN_EXPERIMENTAL -> WoodyTracingFilter.CIPHER_TOKEN_ATTRIBUTE;
                    case VAULT_TOKEN_EXPERIMENTAL -> WoodyTracingFilter.VAULT_TOKEN_ATTRIBUTE;
                    default -> null;
                })
                .map(request::getAttribute)
                .orElse(null);
    }

    public TracePolicy resolvePolicy(int port, String path) {
        return endpoints.stream()
                .filter(endpoint -> matches(endpoint, port, path))
                .findFirst()
                .map(endpoint -> buildPolicy(endpoint, port, path))
                .orElse(null);
    }

    private boolean matches(Endpoint endpoint, int port, String path) {
        var portMatches = port == endpoint.getPort();
        var pathMatches = path.startsWith(endpoint.getPath());
        return portMatches && pathMatches;
    }

    private TracePolicy buildPolicy(Endpoint endpoint, int port, String path) {
        var effectiveRequestMode = Optional.ofNullable(endpoint.getRequestHeaderMode()).orElse(DEFAULT_REQUEST_MODE);
        var effectiveResponseMode = Optional.ofNullable(endpoint.getResponseHeaderMode()).orElse(DEFAULT_RESPONSE_MODE);
        var effectivePropagate = Optional.ofNullable(endpoint.getPropagateErrors())
                .orElse(effectiveResponseMode == ResponseHeaderMode.OFF);
        var tokenTtl = Optional.ofNullable(endpoint.getTokenTtl()).map(s -> Duration.ofMinutes(Long.parseLong(s)))
                .orElse(null);
        return new TracePolicy(port, path, effectiveRequestMode, effectiveResponseMode, effectivePropagate,
                endpoint.getDefaultCipherToken(), tokenTtl);
    }

    public record TracePolicy(int port, String path, RequestHeaderMode requestHeaderMode,
                              ResponseHeaderMode responseHeaderMode, boolean propagateErrors, String defaultCipherToken,
                              Duration tokenTtl) {
    }
}
