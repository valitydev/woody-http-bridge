package dev.vality.woody.http.bridge.autoconfigure;

import dev.vality.woody.http.bridge.OtelConfig;
import dev.vality.woody.http.bridge.WoodyTracingConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import({WoodyTracingConfig.class, OtelConfig.class})
public class WoodyHttpBridgeAutoConfiguration {
}
