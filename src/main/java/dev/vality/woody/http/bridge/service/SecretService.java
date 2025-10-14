package dev.vality.woody.http.bridge.service;

import dev.vality.adapter.common.secret.SecretRef;
import dev.vality.adapter.common.secret.VaultSecretService;
import dev.vality.woody.http.bridge.token.TokenPayload;
import org.springframework.beans.factory.annotation.Value;

import java.util.Objects;

public record SecretService(VaultSecretService vaultSecretService, String serviceName) {

    private static final String SECRET_KEY = "secret_key";
    private static final String CIPHER_TOKEN = "cipher_token";

    public String getCipherTokenSecretKey() {
        return vaultSecretService.getSecret(serviceName, new SecretRef(CIPHER_TOKEN, SECRET_KEY)).getValue();
    }

    public TokenPayload getVaultToken(String tokenKey) {
        return vaultSecretService.getSecret(serviceName, new SecretRef(tokenKey, SECRET_KEY)).getValue();
    }
}
