package dev.vality.woody.http.bridge.token;

import jakarta.servlet.http.HttpServletRequest;

public interface VaultTokenKeyExtractor {

    String extractTokenKey(HttpServletRequest request);
}
