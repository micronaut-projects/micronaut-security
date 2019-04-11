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

package io.micronaut.security.oauth2.openid.endpoints.authorization.state.validation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.State;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.StateSerDes;
import io.micronaut.session.Session;
import io.micronaut.session.SessionStore;
import io.micronaut.session.http.SessionForRequest;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Persists the state in the session.
 *
 * @author James Kleeh
 * @since 1.1.0
 */
@Requires(beans = SessionStore.class)
@Requires(property = DefaultStateValidationConfiguration.PREFIX + ".persistence", value = "session")
@Singleton
public class SessionStatePersistence implements StatePersistence {

    private static final String SESSION_KEY = "oauth2State";

    private final SessionStore<Session> sessionStore;
    private final StateSerDes stateSerDes;

    /**
     * @param sessionStore The session store
     * @param stateSerDes The state serdes
     */
    public SessionStatePersistence(SessionStore<Session> sessionStore,
                                   StateSerDes stateSerDes) {
        this.sessionStore = sessionStore;
        this.stateSerDes = stateSerDes;
    }

    @Override
    public Optional<State> retrieveState(HttpRequest<?> request) {
        return SessionForRequest.find(request)
                .flatMap(session -> {
                    Optional<String> state = session.get(SESSION_KEY, String.class);
                    if (state.isPresent()) {
                        session.remove(SESSION_KEY);
                    }
                    return state;
                })
                .flatMap(state -> Optional.ofNullable(stateSerDes.deserialize(state)));
    }

    @Override
    public void persistState(HttpRequest<?> request, State state) {
        String serializedState = stateSerDes.serialize(state);
        if (serializedState != null) {
            Session session = SessionForRequest.find(request).orElse(SessionForRequest.create(sessionStore, request));
            session.put(SESSION_KEY, serializedState);
        }
    }
}
