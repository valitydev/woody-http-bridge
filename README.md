# Woody HTTP Bridge
[![Maven Central](https://img.shields.io/maven-central/v/dev.vality/woody-http-bridge.svg)](https://central.sonatype.com/artifact/dev.vality/woody-http-bridge)

Spring Boot starter that helps applications proxy HTTP calls while preserving Woody tracing context and OpenTelemetry spans.

## Features

- Servlet filter that restores incoming Woody trace headers and propagates them downstream.
- Response handler that maps Woody errors to HTTP responses and enriches outgoing headers.
- Optional OTLP exporter configuration (enabled by default via `otel.*` properties).

## Getting Started

Add the dependency to your project:

```xml
<dependency>
    <groupId>dev.vality</groupId>
    <artifactId>woody-http-bridge</artifactId>
    <version>${woody-http-bridge.version}</version>
</dependency>
```

No additional setup is required: the auto-configuration registers the tracing filter and response handler in servlet environments.

## Configuration

### Tracing

Configure endpoints that should participate in Woody tracing via `woody-http-bridge.tracing`:

```yaml
woody-http-bridge:
  tracing:
    endpoints:
      - path: /api
        port: 8080
```

Key options:

- `woody-http-bridge.enabled` 
- `woody-http-bridge.tracing.endpoints[0].request-header-mode` — how incoming headers are interpreted. Supported values: `OFF`, `WOODY_OR_X_WOODY`, `CIPHER_TOKEN_EXPERIMENTAL`, `VAULT_TOKEN_EXPERIMENTAL`. `OFF` is default.
- `woody-http-bridge.tracing.endpoints[0].response-header-mode` — which headers are written on responses (`OFF`, `WOODY`, `X_WOODY`, `HTTP`). `OFF` is default.
- `woody-http-bridge.tracing.endpoints[0].propagate-errors` — when `true`, exceptions bubble up; otherwise they are converted to Woody error responses.
- `woody-http-bridge.tracing.endpoints[0].default-cipher-token` — optional fallback token (Base64 URL-encoded) used when no token is present in request for `CIPHER_TOKEN_EXPERIMENTAL` mode.
- `woody-http-bridge.tracing.endpoints[0].token-ttl` — optional TTL in minutes for validating decrypted tokens.

Token modes overview:

- `CIPHER_TOKEN_EXPERIMENTAL` — filter extracts an encrypted token from the request (via `CipherTokenExtractor`), decrypts it with `TokenCipher`, validates TTL, restores `traceparent`/`tracestate`, and runs the request inside the recovered context. Bean `CipherTokenExtractor` can be overridden; default implementation reads the last path segment.
- `VAULT_TOKEN_EXPERIMENTAL` — filter extracts a token key (via `VaultTokenKeyExtractor`), loads a plain `TokenPayload` from `SecretService` (backed by Vault), validates TTL, and restores tracing. Bean `VaultTokenKeyExtractor` can be overridden; default implementation reads the last path segment.
- `SecretService` keeps Vault tokens in structured form (trace ids, span ids, `traceparent`, `tracestate`) and caches the cipher secret key for encrypted mode.

#### Customising token location

Both token modes delegate the lookup to Spring beans so that consumers decide where the token or token key lives. Provide your own `CipherTokenExtractor` or `VaultTokenKeyExtractor` bean to switch to a different transport channel.

Examples:

```java
@Component
class HeaderTokenExtractor implements CipherTokenExtractor {
    @Override
    public String extractToken(HttpServletRequest request) {
        return request.getHeader("X-Cipher-Token");
    }
}
```

```java
@Component
class QueryTokenKeyExtractor implements VaultTokenKeyExtractor {
    @Override
    public String extractTokenKey(HttpServletRequest request) {
        return request.getParameter("vaultKey");
    }
}
```

```java
@Component
class BodyTokenExtractor implements CipherTokenExtractor {
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String extractToken(HttpServletRequest request) {
        try {
            var node = mapper.readTree(request.getInputStream());
            return node.path("cipherToken").asText(null);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to read cipher token", ex);
        }
    }
}
```

Any of these beans automatically override the defaults registered by the starter.

To change how an inbound token is located (e.g., URL segment vs. header vs. body), provide your own Spring beans implementing `CipherTokenExtractor` or `VaultTokenKeyExtractor` which will replace the defaults automatically.

For `CIPHER_TOKEN_EXPERIMENTAL` it is common to embed the encrypted token directly into a callback URL. The following Java example mirrors the Kotlin helper shown in the comments and appends the encrypted token as the last path segment:

```java
@Service
@RequiredArgsConstructor
public class CallbackUrlManager {

    private final AdapterCustomProperties properties;
    private final TokenCipher tokenCipher;
    private final SecretService secretService;
    private final int restPort;
    private final String restEndpoint;

    public String initCallbackUrl(TokenPayload payload) {
        return buildUrl(properties.getPathCallbackUrl(), encrypt(payload));
    }

    public String initRedirectUrl(TokenPayload payload) {
        return buildUrl(properties.getPathRedirectUrl(), encrypt(payload));
    }

    private String encrypt(TokenPayload payload) {
        String secret = secretService.getCipherTokenSecretKey(restPort, restEndpoint);
        return tokenCipher.encrypt(payload, secret);
    }

    private String buildUrl(String path, String token) {
        return UriComponentsBuilder
                .fromUriString(properties.getCallbackUrl())
                .path(path)
                .pathSegment(token)
                .toUriString();
    }
}
```

Vault integration is optional. To bootstrap the provided Vault support enable it explicitly:

```yaml
vault:
  enabled: true
  uri: https://vault.empayre.com:443
  token: "xxx"
```

When disabled (default), the application must provide its own `VaultSecretService`/`SecretService` beans if `VAULT_TOKEN` mode is required.

### OpenTelemetry

The starter exposes an OTLP exporter that can be controlled with `otel.*` properties:

```yaml
otel:
  enabled: true
  resource: http://collector:4318/v1/traces
  timeout: 60000
```

Disable telemetry entirely by setting `otel.enabled=false`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
