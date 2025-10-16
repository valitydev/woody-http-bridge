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

    /**
     * Controls how incoming requests are inspected to recover Woody tracing context.
     */
    public enum RequestHeaderMode {
        /**
         * Disable request enrichment entirely. Incoming Woody headers or tokens are ignored and a fresh context is
         * created for every request.
         */
        OFF,
        /**
         * Accept tracing headers in the Woody canonical form ("Woody-") or the external "X-Woody-" aliases. Headers
         * are passed through as-is without token processing.
         */
        WOODY_OR_X_WOODY,
        /**
         * Expect an encrypted token that is resolved via {@code CipherTokenExtractor} and decrypted with {@link
         * dev.vality.woody.http.bridge.token.TokenCipher}. The resulting {@link TokenPayload} provides the trace
         * context. Remember that encrypted tokens can be long (especially when Base64 URL encoded) and might exceed
         * storage limits for certain transports such as URLs restricted to 255 characters.
         */
        CIPHER_TOKEN_EXPERIMENTAL,
        /**
         * Expect a token key that {@code VaultTokenKeyExtractor} resolves and {@link
         * dev.vality.woody.http.bridge.service.SecretService} loads from Vault, yielding a {@link TokenPayload}
         * containing tracing data. Be mindful that high-traffic services or long-lived tokens can place significant
         * load on Vault due to the volume of stored entries.
         */
        VAULT_TOKEN_EXPERIMENTAL
    }

    /**
     * Controls which Woody headers are written back on HTTP responses.
     */
    public enum ResponseHeaderMode {
        /**
         * Disable response propagation. No Woody headers are emitted.
         */
        OFF,
        /**
         * Emit internal Woody headers using the canonical "Woody-" prefix.
         */
        WOODY,
        /**
         * Emit external Woody headers using the "X-Woody-" prefix for compatibility with edge proxies.
         */
        X_WOODY,
        /**
         * Emit a reduced HTTP-friendly header set (`traceparent`/`tracestate`) suitable for standard tracing tools.
         */
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
