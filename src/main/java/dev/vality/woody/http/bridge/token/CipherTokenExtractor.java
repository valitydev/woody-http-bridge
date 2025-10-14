package dev.vality.woody.http.bridge.token;

import jakarta.servlet.http.HttpServletRequest;

public interface CipherTokenExtractor {

    String extractToken(HttpServletRequest request);
}
