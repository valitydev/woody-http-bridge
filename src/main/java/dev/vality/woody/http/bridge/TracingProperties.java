package dev.vality.woody.http.bridge;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Getter
@Setter
@Component
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

    }

    public enum RequestHeaderMode {
        OFF,
        WOODY_OR_X_WOODY
    }

    public enum ResponseHeaderMode {
        OFF,
        WOODY,
        X_WOODY,
        HTTP
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
        return new TracePolicy(port, path, effectiveRequestMode, effectiveResponseMode, effectivePropagate);
    }

    public record TracePolicy(int port, String path, RequestHeaderMode requestHeaderMode,
                              ResponseHeaderMode responseHeaderMode, boolean propagateErrors) {
    }
}
