package dev.vality.woody.http.bridge.service;

import dev.vality.adapter.common.secret.SecretRef;
import dev.vality.adapter.common.secret.VaultSecretService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

public class SecretService {
    private static final String SECRET_KEY = "secret_key";
    private static final String CIPHER_TOKEN = "cipher_token";

    private final VaultSecretService vaultSecretService;
    private final String serviceName;

    public SecretService(VaultSecretService vaultSecretService,
                        @Value("${spring.application.name}") String serviceName) {
        this.vaultSecretService = vaultSecretService;
        this.serviceName = serviceName;
    }

    public String getCipherTokenSecretKey() {
        return vaultSecretService.getSecret(serviceName, new SecretRef(CIPHER_TOKEN, SECRET_KEY)).getValue();
    }
}
