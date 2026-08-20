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

/**
 * Generates unpredictable values for CSP nonce source expressions.
 *
 * <p>The filter generates one nonce per request, exposes it through {@link #CSP_NONCE_ATTRIBUTE},
 * and uses the same value in the {@code script-src} response directive. Views can use that request
 * attribute as the {@code nonce} attribute of trusted script elements.</p>
 *
 * @since 5.4.0
 */
public interface CspNonceGenerator {
    /**
     * Request attribute and view-model key under which the CSP nonce is stored.
     */
    String CSP_NONCE_ATTRIBUTE = "cspNonce";

    /**
     * @param request the request for which the nonce is generated
     * @return an unpredictable nonce value, unique to the request
     */
    String generateNonce(HttpRequest<?> request);
}
