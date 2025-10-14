# Woody HTTP Bridge

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

Configure endpoints that should participate in Woody tracing via `woody-http-bridge`:

```yaml
woody-http-bridge:
  tracing:
    endpoints:
      - path: /api
        port: 8080
        request-header-mode: WOODY_OR_X_WOODY
        response-header-mode: HTTP
        propagate-errors: false
```

Disable telemetry entirely by setting `woody-http-bridge.enabled=false`.

Key options:

- `request-header-mode` — how incoming headers are interpreted (`OFF`, `WOODY_OR_X_WOODY`).
- `response-header-mode` — which headers are written on responses (`OFF`, `WOODY`, `X_WOODY`, `HTTP`).
- `propagate-errors` — when `true`, exceptions bubble up; otherwise they are converted to Woody error responses.

### OpenTelemetry

The starter exposes an OTLP exporter that can be controlled with `otel.*` properties:

```yaml
otel:
  resource: http://collector:4318/v1/traces
  timeout: 60000
```

Disable telemetry entirely by setting `otel.enabled=false`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
# Woody HTTP Bridge
