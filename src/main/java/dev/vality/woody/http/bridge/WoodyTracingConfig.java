package dev.vality.woody.http.bridge;

import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.properties.TracingProperties;
import dev.vality.woody.http.bridge.service.SecretService;
import dev.vality.woody.http.bridge.token.CipherTokenExtractor;
import dev.vality.woody.http.bridge.token.CipherTokenExtractorImpl;
import dev.vality.woody.http.bridge.token.TokenCipher;
import dev.vality.woody.http.bridge.token.VaultTokenKeyExtractor;
import dev.vality.woody.http.bridge.token.VaultTokenKeyExtractorImpl;
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
import org.springframework.lang.Nullable;

@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(value = "woody-http-bridge.enabled", havingValue = "true", matchIfMissing = true)
@ConditionalOnClass({FilterRegistrationBean.class, WoodyTracingFilter.class})
@EnableConfigurationProperties(TracingProperties.class)
/**
 * Spring configuration that wires Woody tracing infrastructure when servlet based web applications
 * enable {@code woody-http-bridge}. Beans declared here provide the tracing filter, token helpers and
 * response handler while remaining conditional on user customisations.
 */
public class WoodyTracingConfig {

    /**
     * Creates a handler for mapping Woody trace outcomes to HTTP responses when no custom bean is present.
     */
    @Bean
    @ConditionalOnMissingBean
    public WoodyTraceResponseHandler woodyTraceResponseHandler() {
        return new WoodyTraceResponseHandler();
    }

    /**
     * Supplies the default cipher responsible for decrypting tracing payloads.
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenCipher tokenCipher() {
        return new TokenCipher();
    }

    /**
     * Registers the default cipher token extractor if the application has not overridden it.
     */
    @Bean
    @ConditionalOnMissingBean(CipherTokenExtractor.class)
    public CipherTokenExtractor cipherTokenExtractor() {
        return new CipherTokenExtractorImpl();
    }

    /**
     * Registers the default vault token key extractor when no alternative bean is provided.
     */
    @Bean
    @ConditionalOnMissingBean(VaultTokenKeyExtractor.class)
    public VaultTokenKeyExtractor vaultTokenKeyExtractor() {
        return new VaultTokenKeyExtractorImpl();
    }

    /**
     * Creates the main Woody tracing filter that restores incoming contexts and enriches responses.
     */
    @Bean
    @ConditionalOnMissingBean
    public WoodyTracingFilter woodyTracingFilter(
            TracingProperties tracingProperties,
            WoodyTraceResponseHandler woodyTraceResponseHandler,
            TokenCipher tokenCipher,
            @Nullable SecretService secretService,
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

    /**
     * Registers the tracing filter within the servlet filter chain when custom registration is absent.
     */
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
