package dev.vality.woody.http.bridge;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Optional;

public final class JwtTokenDetailsExtractor {

    private static final String PREFERRED_USERNAME = "preferred_username";
    private static final String EMAIL = "email";
    private static final String ISSUER = "iss";

    private JwtTokenDetailsExtractor() {
    }

    public static Optional<JwtTokenDetails> extractFromContext(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            return Optional.empty();
        }
        var token = jwtAuthentication.getToken();
        return Optional.of(new JwtTokenDetails(
                token.getClaimAsString(JwtClaimNames.SUB),
                token.getClaimAsString(PREFERRED_USERNAME),
                token.getClaimAsString(EMAIL),
                extractRealm(token),
                jwtAuthentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        ));
    }

    private static String extractRealm(Jwt token) {
        var issuer = token.getClaimAsString(ISSUER);
        if (issuer == null || issuer.isBlank()) {
            return null;
        }
        var lastSlash = issuer.lastIndexOf('/');
        if (lastSlash < 0) {
            return issuer;
        }
        return issuer.substring(lastSlash);
    }

    public record JwtTokenDetails(String subject,
                                  String preferredUsername,
                                  String email,
                                  String realm,
                                  List<String> roles) {
    }
}
