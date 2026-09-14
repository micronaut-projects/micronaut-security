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
package io.micronaut.security.oauth2.endpoint.nonce.persistence.session;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues;
import io.micronaut.security.oauth2.endpoint.nonce.DefaultNonceConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.persistence.NoncePersistence;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import java.util.Optional;

/**
 * Persists the nonce in the session. Several in-flight nonces (up to {@link StateKeyedSessionValues#MAX_ENTRIES})
 * are kept, keyed by the nonce of the {@link State} of the login flow they belong to, so that concurrent login flows
 * do not overwrite each other.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = SessionStore.class)
@Requires(property = DefaultNonceConfiguration.PREFIX + ".persistence", value = DefaultNonceConfiguration.PERSISTENCE_SESSION)
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
        return retrieveNonce(request, null);
    }

    @Override
    public Optional<String> retrieveNonce(HttpRequest<?> request, @Nullable State callbackState) {
        return SessionForRequest.find(request)
                .flatMap(session -> StateKeyedSessionValues.<String>remove(session, SESSION_KEY, StateKeyedSessionValues.keyForCallbackState(callbackState)));
    }

    @Override
    public void persistNonce(HttpRequest<?> request, MutableHttpResponse response, String nonce) {
        Session session = SessionForRequest.find(request).orElseGet(() ->
                SessionForRequest.create(sessionStore, request));
        StateKeyedSessionValues.put(session, SESSION_KEY, StateKeyedSessionValues.keyForLoginRequest(request), nonce);
    }
}
