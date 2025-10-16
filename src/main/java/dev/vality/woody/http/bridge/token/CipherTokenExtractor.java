package dev.vality.woody.http.bridge.token;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Strategy interface used by {@code CIPHER_TOKEN_EXPERIMENTAL} mode to discover the encrypted token that should be
 * decrypted by {@link TokenCipher}. The starter ships with {@link CipherTokenExtractorImpl} which reads the token from
 * the final path segment, but applications are free to supply their own bean and choose any transport channel that
 * fits their API contract (path, header, query parameter, body, and so on).
 *
 * <p>Example implementations:</p>
 * <ul>
 *     <li><strong>Path segment (default):</strong>
 *     <pre>{@code
 *     @Component
 *     class PathTokenExtractor implements CipherTokenExtractor {
 *         @Override
 *         public String extractToken(HttpServletRequest request) {
 *             return request.getRequestURI().substring(request.getRequestURI().lastIndexOf('/') + 1);
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>HTTP header:</strong>
 *     <pre>{@code
 *     @Component
 *     class HeaderTokenExtractor implements CipherTokenExtractor {
 *         @Override
 *         public String extractToken(HttpServletRequest request) {
 *             return request.getHeader("X-Cipher-Token");
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>Query parameter:</strong>
 *     <pre>{@code
 *     @Component
 *     class QueryTokenExtractor implements CipherTokenExtractor {
 *         @Override
 *         public String extractToken(HttpServletRequest request) {
 *             return request.getParameter("cipherToken");
 *         }
 *     }
 *     }</pre>
 *     </li>
 *     <li><strong>Request body (JSON field):</strong>
 *     <pre>{@code
 *     @Component
 *     class BodyTokenExtractor implements CipherTokenExtractor {
 *         private final ObjectMapper mapper = new ObjectMapper();
 *
 *         @Override
 *         public String extractToken(HttpServletRequest request) {
 *             try {
 *                 var node = mapper.readTree(request.getInputStream());
 *                 return node.path("cipherToken").asText(null);
 *             } catch (IOException ex) {
 *                 throw new IllegalStateException("Unable to read cipher token", ex);
 *             }
 *         }
 *     }
 *     }</pre>
 *     </li>
 * </ul>
 */
public interface CipherTokenExtractor {

    String extractToken(HttpServletRequest request);
}
