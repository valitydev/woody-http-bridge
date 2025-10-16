package dev.vality.woody.http.bridge.properties;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class TracingPropertiesTest {

    @Test
    void shouldResolveTokenSettings() {
        final var properties = new TracingProperties();
        var endpoint = new TracingProperties.Endpoint();
        endpoint.setPort(8080);
        endpoint.setPath("/api");
        endpoint.setRequestHeaderMode(TracingProperties.RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL);
        endpoint.setResponseHeaderMode(TracingProperties.ResponseHeaderMode.WOODY);
        endpoint.setDefaultCipherToken("fallback");
        endpoint.setTokenTtl("30");
        properties.getEndpoints().add(endpoint);

        var policy = properties.resolvePolicy(8080, "/api/resource");

        assertNotNull(policy);
        assertEquals("/api/resource", policy.path());
        assertEquals(TracingProperties.RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL, policy.requestHeaderMode());
        assertEquals(TracingProperties.ResponseHeaderMode.WOODY, policy.responseHeaderMode());
        assertFalse(policy.propagateErrors());
        assertEquals("fallback", policy.defaultCipherToken());
        assertEquals(Duration.ofMinutes(30), policy.tokenTtl());
    }

    @Test
    void shouldReturnNullForTokenSettingsWhenNotConfigured() {
        final var properties = new TracingProperties();
        var endpoint = new TracingProperties.Endpoint();
        endpoint.setPort(8080);
        endpoint.setPath("/api");
        endpoint.setRequestHeaderMode(TracingProperties.RequestHeaderMode.CIPHER_TOKEN_EXPERIMENTAL);
        properties.getEndpoints().add(endpoint);

        var policy = properties.resolvePolicy(8080, "/api/resource");

        assertNotNull(policy);
        assertNull(policy.defaultCipherToken());
        assertNull(policy.tokenTtl());
    }
}
