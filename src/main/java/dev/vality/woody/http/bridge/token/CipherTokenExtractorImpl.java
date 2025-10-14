package dev.vality.woody.http.bridge.token;

import jakarta.servlet.http.HttpServletRequest;

import static dev.vality.woody.http.bridge.tracing.WoodyTracingFilter.getRequestPath;

public class CipherTokenExtractorImpl implements CipherTokenExtractor {

    @Override
    public String extractToken(HttpServletRequest request) {
        var path = getRequestPath(request);
        if (path.isBlank()) {
            return null;
        }
        var lastSlash = path.lastIndexOf('/');
        if (lastSlash < 0 || lastSlash + 1 >= path.length()) {
            return null;
        }
        var token = path.substring(lastSlash + 1);
        var queryIndex = token.indexOf('?');
        return queryIndex >= 0 ? token.substring(0, queryIndex) : token;
    }
}
