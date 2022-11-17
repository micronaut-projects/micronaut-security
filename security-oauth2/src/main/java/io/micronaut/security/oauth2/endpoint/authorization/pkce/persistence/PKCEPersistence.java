/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.PKCE;

import java.util.Optional;

/**
 * Persists the Proof of Key Exchange (PKCE) for later retrieval.
 *
 * @author Nemanja Mikic
 * @since 3.9.0
 */
public interface PKCEPersistence {

    /**
     * Retrieves and removes the pkce from persistence.
     *
     * @param request The request
     * @return The optional PKCE code_verifier
     */
    Optional<String> retrieve(HttpRequest<?> request);

    /**
     * Persists the PKCE for later retrieval.
     *
     * @param request  The login request
     * @param response The authorization redirect response
     * @param pkce     The PKCE to persist
     */
    void persistPKCE(HttpRequest<?> request, MutableHttpResponse<?> response, PKCE pkce);
}
