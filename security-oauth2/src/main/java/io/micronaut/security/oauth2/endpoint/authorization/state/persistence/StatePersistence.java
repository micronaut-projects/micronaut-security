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
package io.micronaut.security.oauth2.endpoint.authorization.state.persistence;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import org.jspecify.annotations.Nullable;
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
     * Retrieves and removes the state from persistence which corresponds to the state received in the callback.
     * Implementations that can hold several in-flight states (keyed by {@link State#getNonce()}) should override this
     * method to return only the state matching {@code callbackState}. The default implementation ignores
     * {@code callbackState} and delegates to {@link #retrieveState(HttpRequest)}.
     *
     * @param request The callback request
     * @param callbackState The state received in the authorization callback, if any
     * @return The optional state
     * @since 5.4.0
     */
    default Optional<State> retrieveState(HttpRequest<?> request, @Nullable State callbackState) {
        return retrieveState(request);
    }

    /**
     * Persists the state for later retrieval to allow validation.
     *
     * @param request The login request
     * @param response The authorization redirect response
     * @param state The state to persist
     */
    void persistState(HttpRequest<?> request, MutableHttpResponse response, State state);
}
