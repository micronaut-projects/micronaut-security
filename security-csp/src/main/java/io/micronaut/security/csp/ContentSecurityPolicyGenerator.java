/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.csp;

import io.micronaut.http.HttpRequest;
import org.jspecify.annotations.Nullable;

/**
 * Generates a Content Security Policy for an HTTP request.
 *
 * <p>Implementations return a structured {@link ContentSecurityPolicy} rather than a serialized
 * header value. This allows a generator to use request-specific state, such as a nonce, while
 * preserving directive order. The CSP server filter serializes a non-null policy and omits its
 * response header when this generator returns {@code null}.</p>
 *
 * <p>{@link ContentSecurityPolicyDirectiveNames} and {@link ContentSecurityPolicyKeywords} hold the
 * names of standard directives and source expressions to build a policy with.</p>
 *
 * @since 5.6.0
 */
@FunctionalInterface
public interface ContentSecurityPolicyGenerator {
    /**
     * Generates the policy applicable to an HTTP request.
     *
     * <p>The request can supply policy inputs that must vary for every response, including nonce
     * source expressions. Returning {@code null} suppresses the CSP response header for this
     * request.</p>
     *
     * <p>This method is called for every response that matches the CSP filter pattern, typically on
     * the HTTP server's event loop. It must not block: load policies that depend on external data,
     * such as per-tenant policies, ahead of time and cache them.</p>
     *
     * @param request the request for which the policy is generated
     * @return the ordered policy, or {@code null} when no CSP header should be written
     * @since 5.6.0
     */
    @Nullable ContentSecurityPolicy contentSecurityPolicy(HttpRequest<?> request);
}
