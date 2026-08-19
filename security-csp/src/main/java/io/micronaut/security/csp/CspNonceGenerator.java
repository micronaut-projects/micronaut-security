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
 * @since 5.4.0
 */
public interface CspNonceGenerator {
    /**
     * Request attribute and view-model key under which the CSP nonce is stored.
     */
    String CSP_NONCE_ATTRIBUTE = "cspNonce";

    /**
     * @param request the request for which the nonce is generated
     * @return a newly generated nonce value
     */
    String generateNonce(HttpRequest<?> request);
}
