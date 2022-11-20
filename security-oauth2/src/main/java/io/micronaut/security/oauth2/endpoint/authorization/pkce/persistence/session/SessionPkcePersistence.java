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
package io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.session;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.Pkce;
import io.micronaut.security.oauth2.endpoint.authorization.pkce.persistence.PkcePersistence;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Persists the Proof of Key Exchange (PKCE) code_verifier in the session.
 *
 * @author Nemanja Mikic
 * @since 3.9.0
 */
@Requires(beans = SessionStore.class)
@Singleton
public class SessionPkcePersistence implements PkcePersistence {

    private static final String SESSION_KEY = "oauth2pkce";

    private final SessionStore<Session> sessionStore;

    /**
     * @param sessionStore The session store
     */
    public SessionPkcePersistence(SessionStore<Session> sessionStore) {
        this.sessionStore = sessionStore;
    }

    /**
     * Retrieve the code verifier and removes it from the session if present.
     *
     * @param request The request
     * @return The optional PKCE code verifier
     */
    @Override
    @NonNull
    public Optional<String> retrieveCodeVerifier(@NonNull HttpRequest<?> request) {
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
    public void persistPkce(@NonNull HttpRequest<?> request,
                            @NonNull MutableHttpResponse<?> response,
                            @NonNull Pkce pkce) {
        Session session = SessionForRequest.find(request)
            .orElseGet(() -> SessionForRequest.create(sessionStore, request));
        session.put(SESSION_KEY, pkce.getCodeVerifier());
    }
}
