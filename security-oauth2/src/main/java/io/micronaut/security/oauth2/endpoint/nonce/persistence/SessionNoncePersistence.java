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

package io.micronaut.security.oauth2.endpoint.nonce.persistence;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Persists the state in the session.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = SessionStore.class)
@Requires(property = DefaultNonceConfiguration.PREFIX + ".persistence", value = "session")
@Singleton
public class SessionNoncePersistence implements NoncePersistence {

    private static final String SESSION_KEY = "openIdNonce";

    private final SessionStore<Session> sessionStore;

    /**
     * @param sessionStore The session store
     */
    public SessionNoncePersistence(SessionStore<Session> sessionStore) {
        this.sessionStore = sessionStore;
    }

    @Override
    public Optional<String> retrieveNonce(HttpRequest<?> request) {
        return SessionForRequest.find(request)
                .flatMap(session -> {
                    Optional<String> state = session.get(SESSION_KEY, String.class);
                    if (state.isPresent()) {
                        session.remove(SESSION_KEY);
                    }
                    return state;
                });
    }

    @Override
    public void persistNonce(HttpRequest<?> request, MutableHttpResponse response, String state) {
        Session session = SessionForRequest.find(request).orElseGet(() ->
                SessionForRequest.create(sessionStore, request));
        session.put(SESSION_KEY, state);
    }
}
