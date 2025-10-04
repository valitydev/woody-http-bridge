# Woody HTTP Bridge

## Background

- Gateway services such as Wachter receive HTTP requests that may already contain Woody (`woody.*`, `x-woody-*`) and W3C (`traceparent`) tracing headers.
- Current Wachter implementation normalizes incoming headers, hydrates Woody `TraceContext`, ensures OpenTelemetry SERVER spans are created, and forwards normalized headers to downstream Woody RPC clients.
- OpenTelemetry requires explicit SERVER span lifecycle management (status, errors, `span.end()`), while Woody RPC handles span lifecycle internally once the Woody flow is forked.
- HTTP clients that call Wachter expect plain HTTP responses; Woody-specific response metadata is only required on the RPC leg.

## Concept

Create a reusable "Woody HTTP Bridge" starter that bridges HTTP traffic with Woody and OpenTelemetry tracing so that any HTTP gateway can:

1. Extract and normalize Woody/W3C headers from incoming HTTP requests.
2. Hydrate the current Woody `TraceContext` before executing business logic.
3. Ensure an OpenTelemetry SERVER span is started, annotated, and completed per spec.
4. Provide helpers for forwarding normalized headers when making downstream Woody RPC calls.

## Implementation Plan

1. **Project Setup**
   - Publish a `woody-http-bridge` library (Maven/Gradle) with starter-style auto-configuration.
   - Depend on `woody-java`, `opentelemetry-api`, and Servlet/Spring Web abstractions.

2. **Incoming Request Pipeline**
   - `WoodyHttpBridgeFilter` (Servlet `Filter` or `OncePerRequestFilter`) orchestrating header normalization, `TraceContext` hydration, and telemetry handling.
   - Pluggable `NormalizedHeadersStore` (default: request attributes) to persist merged headers for downstream usage.
   - `HeaderNormalizer` to merge `x-woody-*` into `woody.*`, capture `traceparent`, JWT metadata, and deadlines.
   - `TraceContextHydrator` to copy normalized IDs, deadline, and user identity extensions into the current Woody span.

3. **OpenTelemetry Integration**
   - `TelemetryBridge` responsible for starting/stopping SERVER spans, extracting parents (via `HttpServletRequestTextMapGetter`), injecting missing `traceparent` (`MapTextMapSetter`), and recording status/errors.

4. **Outgoing Request Helpers**
   - `OutgoingHeadersProvider` that combines stored normalized headers with live `TraceContext` values.
   - Optional interceptors for `RestClient`, `WebClient`, or manual helper to inject headers into arbitrary HTTP/RPC clients.

5. **Configuration & Extensibility**
   - Spring Boot auto-configuration with properties to enable/disable components, customize header mappings, and swap storage strategies.
   - Fallback manual registration API for non-Spring environments.

6. **Testing & Examples**
   - Unit tests for normalization, hydration, telemetry, and outgoing header composition.
   - Integration test with Mock MVC to verify end-to-end propagation.
   - Example application demonstrating gateway usage.

## Next Steps

- Align on API surface (naming, extension points) before coding.
- Decide which HTTP clients to support out of the box for outgoing propagation.
- Prepare publishing pipeline (group ID, versioning) and documentation once implementation is ready.
