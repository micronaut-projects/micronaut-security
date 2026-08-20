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

@FunctionalInterface
/**
 * Generates the request-specific {@code script-src} directive.
 *
 * <p>Implementations commonly use a request nonce, but may instead generate hash- or
 * host-based policies. Return {@code null} when no {@code script-src} directive should be sent.</p>
 *
 * @since 5.4.0
 */
public interface ScriptSrcGenerator {
    /**
     * Generates the {@code script-src} directive for a request.
     *
     * @param request the request associated with the response policy
     * @return the directive to add, or {@code null} when omitted
     * @since 5.4.0
     */
    @Nullable ContentSecurityPolicyDirective generateScriptSrcDirective(HttpRequest<?> request);
}
