package dev.vality.woody.http.bridge;

import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.service.SecretService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.vault.config.EnvironmentVaultConfiguration;

@Configuration
@ConditionalOnClass(EnvironmentVaultConfiguration.class)
@ConditionalOnProperty(value = "vault.enabled", havingValue = "true")
@Import(EnvironmentVaultConfiguration.class)
public class VaultConfig {

    @Bean
    @ConditionalOnMissingBean
    public VaultSecretService vaultSecretService(EnvironmentVaultConfiguration environmentVaultConfiguration) {
        return new VaultSecretService(environmentVaultConfiguration.vaultTemplate());
    }

    @Bean
    @ConditionalOnClass(VaultSecretService.class)
    @ConditionalOnMissingBean
    public SecretService secretService(VaultSecretService vaultSecretService,
                                       @Value("${spring.application.name}") String serviceName) {
        return new SecretService(vaultSecretService, serviceName);
    }
}
