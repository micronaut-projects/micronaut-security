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
package io.micronaut.security.oauth2.endpoint.authorization.state.persistence.session;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StateKeyedSessionValues;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import java.util.Optional;

/**
 * Persists the state in the session. Several in-flight states (up to {@link StateKeyedSessionValues#MAX_ENTRIES})
 * are kept, keyed by {@link State#getNonce()}, so that concurrent login flows do not overwrite each other.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = SessionStore.class)
@Singleton
public class SessionStatePersistence implements StatePersistence {

    private static final String SESSION_KEY = "oauth2State";

    private final SessionStore<Session> sessionStore;

    /**
     * @param sessionStore The session store
     */
    public SessionStatePersistence(SessionStore<Session> sessionStore) {
        this.sessionStore = sessionStore;
    }

    @Override
    public Optional<State> retrieveState(HttpRequest<?> request) {
        return retrieveState(request, null);
    }

    @Override
    public Optional<State> retrieveState(HttpRequest<?> request, @Nullable State callbackState) {
        return SessionForRequest.find(request)
                .flatMap(session -> StateKeyedSessionValues.<State>remove(session, SESSION_KEY, StateKeyedSessionValues.keyForCallbackState(callbackState)));
    }

    @Override
    public void persistState(HttpRequest<?> request, MutableHttpResponse response, State state) {
        Session session = SessionForRequest.find(request).orElseGet(() -> SessionForRequest.create(sessionStore, request));
        StateKeyedSessionValues.put(session, SESSION_KEY, state.getNonce(), state);
    }
}
