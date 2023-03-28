/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.oauth2.endpoint.nonce.persistence;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import java.util.Optional;

/**
 * Persists the nonce for later retrieval necessary for validation.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface NoncePersistence {

    /**
     * Retrieves and removes the nonce from persistence.
     *
     * @param request The request
     * @return The optional nonce
     */
    Optional<String> retrieveNonce(HttpRequest<?> request);

    /**
     * Persists the nonce for later retrieval to allow validation.
     *
     * @param request The login request
     * @param response The authorization redirect response
     * @param nonce The nonce to persist
     */
    void persistNonce(HttpRequest<?> request, MutableHttpResponse response, String nonce);
}
