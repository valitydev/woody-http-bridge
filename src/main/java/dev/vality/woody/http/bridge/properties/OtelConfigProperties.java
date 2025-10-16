package dev.vality.woody.http.bridge.properties;

import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "otel")
public class OtelConfigProperties {

    @NotNull
    private String resource;
    @NotNull
    private Long timeout;

}
