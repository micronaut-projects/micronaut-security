/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.authorization.state.persistence;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;

import java.util.Optional;

/**
 * Persists the state for later retrieval necessary for validation.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public interface StatePersistence {

    /**
     * Retrieves and removes the state from persistence.
     *
     * @param request The request
     * @return The optional state
     */
    Optional<State> retrieveState(HttpRequest<?> request);

    /**
     * Persists the state for later retrieval to allow validation.
     *
     * @param request The login request
     * @param response The authorization redirect response
     * @param state The state to persist
     */
    void persistState(HttpRequest<?> request, MutableHttpResponse response, State state);
}
