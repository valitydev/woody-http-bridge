package dev.vality.woody.http.bridge;

import dev.vality.woody.http.bridge.properties.TracingProperties;
import dev.vality.woody.http.bridge.tracing.WoodyTraceResponseHandler;
import dev.vality.woody.http.bridge.tracing.WoodyTracingFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class WoodyTracingConfig {

    @Bean
    public FilterRegistrationBean<WoodyTracingFilter> woodyTracingFilter(TracingProperties tracingProperties) {
        var woodyTraceResponseHandler = new WoodyTraceResponseHandler();
        var filter = new WoodyTracingFilter(tracingProperties, woodyTraceResponseHandler);
        var registrationBean = new FilterRegistrationBean<>(filter);
        registrationBean.setOrder(-50);
        registrationBean.setName("woodyTracingFilter");
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}
