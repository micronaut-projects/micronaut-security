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

package io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence;

import javax.inject.Singleton;
import java.util.Optional;

/**
 * Persists the state value in a cookie.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class CookieStatePersistence implements StatePersistence {

    private final StateSerDes stateSerDes;
    private final CookieStatePersistenceConfiguration configuration;

    /**
     * @param stateSerDes The state serializer/deserializer
     * @param configuration The cookie configuration
     */
    public CookieStatePersistence(StateSerDes stateSerDes,
                                  CookieStatePersistenceConfiguration configuration) {
        this.stateSerDes = stateSerDes;
        this.configuration = configuration;
    }

    @Override
    public Optional<State> retrieveState(HttpRequest<?> request) {
        Cookie cookie = request.getCookies().get(configuration.getCookieName());
        return Optional.ofNullable(cookie)
                .map(c -> stateSerDes.deserialize(c.getValue()));
    }

    @Override
    public void persistState(HttpRequest<?> request, MutableHttpResponse response, State state) {
        String serializedState = stateSerDes.serialize(state);
        if (serializedState != null) {
            Cookie cookie = Cookie.of(configuration.getCookieName(), serializedState);
            cookie.configure(configuration, request.isSecure());
            response.cookie(cookie);
        }
    }
}
