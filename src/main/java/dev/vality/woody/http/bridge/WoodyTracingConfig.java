package dev.vality.woody.http.bridge;

import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.properties.TracingProperties;
import dev.vality.woody.http.bridge.service.SecretService;
import dev.vality.woody.http.bridge.token.*;
import dev.vality.woody.http.bridge.tracing.WoodyTraceResponseHandler;
import dev.vality.woody.http.bridge.tracing.WoodyTracingFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(value = "woody-http-bridge.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({FilterRegistrationBean.class, WoodyTracingFilter.class})
@EnableConfigurationProperties(TracingProperties.class)
public class WoodyTracingConfig {

    @Bean
    @ConditionalOnMissingBean
    public WoodyTraceResponseHandler woodyTraceResponseHandler() {
        return new WoodyTraceResponseHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenCipher tokenCipher() {
        return new TokenCipher();
    }

    @Bean
    @ConditionalOnMissingBean(CipherTokenExtractor.class)
    public CipherTokenExtractor cipherTokenExtractor() {
        return new CipherTokenExtractorImpl();
    }

    @Bean
    @ConditionalOnMissingBean(VaultTokenKeyExtractor.class)
    public VaultTokenKeyExtractor vaultTokenKeyExtractor() {
        return new VaultTokenKeyExtractorImpl();
    }

    @Bean
    @ConditionalOnClass(VaultSecretService.class)
    @ConditionalOnMissingBean
    public SecretService secretService(VaultSecretService vaultSecretService,
                                       @Value("${spring.application.name}") String serviceName) {
        return new SecretService(vaultSecretService, serviceName);
    }

    @Bean
    @ConditionalOnMissingBean
    public WoodyTracingFilter woodyTracingFilter(
            TracingProperties tracingProperties,
            WoodyTraceResponseHandler woodyTraceResponseHandler,
            TokenCipher tokenCipher,
            SecretService secretService,
            CipherTokenExtractor cipherTokenExtractor,
            VaultTokenKeyExtractor vaultTokenKeyExtractor) {
        return new WoodyTracingFilter(
                tracingProperties,
                woodyTraceResponseHandler,
                tokenCipher,
                secretService,
                cipherTokenExtractor,
                vaultTokenKeyExtractor
        );
    }

    @Bean
    @ConditionalOnMissingBean(name = "woodyTracingFilterRegistration")
    public FilterRegistrationBean<WoodyTracingFilter> woodyTracingFilterRegistration(
            WoodyTracingFilter woodyTracingFilter) {
        var registrationBean = new FilterRegistrationBean<>(woodyTracingFilter);
        registrationBean.setOrder(-50);
        registrationBean.setName("woodyTracingFilter");
        registrationBean.addUrlPatterns("/*");
        return registrationBean;
    }
}
