package dev.vality.woody.http.bridge;

import dev.vality.woody.http.bridge.properties.OtelConfigProperties;
import io.opentelemetry.api.GlobalOpenTelemetry;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor;
import io.opentelemetry.sdk.trace.samplers.Sampler;
import io.opentelemetry.semconv.ServiceAttributes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Slf4j
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(value = "otel.enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(OtelConfigProperties.class)
@RequiredArgsConstructor
public class OtelConfig {

    private final OtelConfigProperties otelConfigProperties;

    @Value("${spring.application.name}")
    private String applicationName;

    @Bean
    @ConditionalOnMissingBean
    public OpenTelemetry openTelemetryConfig() {
        var resource = Resource.getDefault()
                .merge(Resource.create(Attributes.of(ServiceAttributes.SERVICE_NAME, applicationName)));
        var sdkTracerProvider = SdkTracerProvider.builder()
                .addSpanProcessor(BatchSpanProcessor.builder(OtlpHttpSpanExporter.builder()
                                .setEndpoint(otelConfigProperties.getResource())
                                .setTimeout(Duration.ofMillis(otelConfigProperties.getTimeout()))
                                .build())
                        .build())
                .setSampler(Sampler.alwaysOn())
                .setResource(resource)
                .build();
        var openTelemetrySdk = OpenTelemetrySdk.builder()
                .setTracerProvider(sdkTracerProvider)
                .setPropagators(ContextPropagators.create(W3CTraceContextPropagator.getInstance()))
                .build();
        registerGlobalOpenTelemetry(openTelemetrySdk);
        return openTelemetrySdk;
    }

    private static void registerGlobalOpenTelemetry(OpenTelemetry openTelemetry) {
        try {
            GlobalOpenTelemetry.set(openTelemetry);
        } catch (Throwable ex) {
            log.warn("Please initialize the ObservabilitySdk before starting the application", ex);
            GlobalOpenTelemetry.resetForTest();
            try {
                GlobalOpenTelemetry.set(openTelemetry);
            } catch (Throwable ex1) {
                log.warn("Unable to set GlobalOpenTelemetry", ex1);
            }
        }
    }
}
