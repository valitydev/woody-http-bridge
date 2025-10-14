package dev.vality.woody.http.bridge.tracing;

import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClient;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "otel.enabled=false",
        "auth.enabled=false"
})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Import(ServletInstrumentationTestConfig.class)
class ServletInstrumentationTest {

    private static final AttributeKey<String> HTTP_METHOD = AttributeKey.stringKey("http.request.method");
    private static final AttributeKey<Long> HTTP_STATUS_LONG = AttributeKey.longKey("http.response.status_code");

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private RestClient restClient;

    @Autowired
    private InMemorySpanExporter spanExporter;

    @Autowired
    private SdkTracerProvider tracerProvider;

    @BeforeEach
    void setUp() {
        spanExporter.reset();
    }

    @AfterEach
    void tearDown() {
        spanExporter.reset();
    }

    @AfterAll
    void shutdownTelemetry() {
        tracerProvider.close();
        spanExporter.shutdown();
        GlobalOpenTelemetry.resetForTest();
    }

    @Test
    void shouldCaptureServletSpanWithHttpAttributes() throws InterruptedException {
        int statusCode;
        try {
            var response = restClient.get()
                    .uri("http://localhost:" + port + "/test/ping")
                    .retrieve()
                    .toEntity(String.class);
            statusCode = response.getStatusCode().value();
        } catch (HttpStatusCodeException ex) {
            statusCode = ex.getStatusCode().value();
        }

        assertTrue(statusCode > 0);

        List<SpanData> spans = waitForSpans();
        SpanData serverSpan = spans.stream()
                .filter(span -> span.getKind() == SpanKind.SERVER)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected SERVER span"));

        assertEquals("GET", serverSpan.getAttributes().get(HTTP_METHOD));
        int expectedStatus = statusCode;
        Long statusLong = serverSpan.getAttributes().get(HTTP_STATUS_LONG);
        if (statusLong != null) {
            assertEquals(expectedStatus, statusLong.intValue());
        } else {
            assertEquals(expectedStatus, serverSpan.getAttributes().get(HTTP_STATUS_LONG));
        }
        assertTrue(serverSpan.getName().contains("/test/ping"));

        SpanData clientSpan = spans.stream()
                .filter(span -> span.getKind() == SpanKind.CLIENT)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected CLIENT span"));

        assertEquals("GET", clientSpan.getAttributes().get(HTTP_METHOD));
        Long clientStatusLong = clientSpan.getAttributes().get(HTTP_STATUS_LONG);
        if (clientStatusLong != null) {
            assertEquals(expectedStatus, clientStatusLong.intValue());
        } else {
            assertEquals(expectedStatus, clientSpan.getAttributes().get(HTTP_STATUS_LONG));
        }
    }

    private List<SpanData> waitForSpans() throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
        while ((spanExporter.getFinishedSpanItems().size() < 2) && System.nanoTime() < deadline) {
            Thread.sleep(25);
        }
        List<SpanData> spans = spanExporter.getFinishedSpanItems();
        if (spans.size() < 2) {
            fail("Expected client and server spans to be exported");
        }
        return spans;
    }
}
