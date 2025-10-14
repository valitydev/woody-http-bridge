package dev.vality.woody.http.bridge;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "otel")
public class OtelConfigProperties {

    private String resource;
    private Long timeout;

}
