package dev.vality.woody.http.bridge.token;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Strategy interface used by {@code VAULT_TOKEN_EXPERIMENTAL} mode to locate the lookup key that {@link SecretService}
 * later resolves into a {@link TokenPayload}. The provided {@link VaultTokenKeyExtractorImpl} grabs the final path
 * segment, however consumers should override the bean if their token key arrives via alternative transports.
 *
 * <p>Example implementations:</p>
 * <ul>
 *     <li><strong>Path segment (default):</strong>
 *     <pre>{@code
 *     @Component
 *     class PathTokenKeyExtractor implements VaultTokenKeyExtractor {
 *         @Override
 *         public String extractTokenKey(HttpServletRequest request) {
 *             return request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>HTTP header:</strong>
 *     <pre>{@code
 *     @Component
 *     class HeaderTokenKeyExtractor implements VaultTokenKeyExtractor {
 *         @Override
 *         public String extractTokenKey(HttpServletRequest request) {
 *             return request.getHeader("X-Woody-Vault-Key");
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>Query parameter:</strong>
 *     <pre>{@code
 *     @Component
 *     class QueryTokenKeyExtractor implements VaultTokenKeyExtractor {
 *         @Override
 *         public String extractTokenKey(HttpServletRequest request) {
 *             return request.getParameter("vaultKey");
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>Request body (JSON field):</strong>
 *     <pre>{@code
 *     @Component
 *     class BodyTokenKeyExtractor implements VaultTokenKeyExtractor {
 *         private final ObjectMapper mapper = new ObjectMapper();
 *
 *         @Override
 *         public String extractTokenKey(HttpServletRequest request) {
 *             try {
 *                 var node = mapper.readTree(request.getInputStream());
 *                 return node.path("vaultKey").asText(null);
 *             } catch (IOException ex) {
 *                 throw new IllegalStateException("Unable to read vault token key", ex);
 *             }
 *         }
 *     }
 *     }</pre>
 *     </li>
 * </ul>
 */
public interface VaultTokenKeyExtractor {

    String extractTokenKey(HttpServletRequest request);
}
