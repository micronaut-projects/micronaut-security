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
package io.micronaut.security.oauth2.endpoint.authorization.state.persistence.cookie;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.oauth2.endpoint.authorization.CookiePersistence;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.authorization.state.StateSerDes;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence;
import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Persists the state value in a cookie.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class CookieStatePersistence extends CookiePersistence implements StatePersistence {

    private final StateSerDes stateSerDes;

    /**
     * @param stateSerDes The state serializer/deserializer
     * @param configuration The cookie configuration
     */
    public CookieStatePersistence(StateSerDes stateSerDes,
                                  CookieStatePersistenceConfiguration configuration) {
        super(configuration);
        this.stateSerDes = stateSerDes;
    }

    @Override
    public Optional<State> retrieveState(HttpRequest<?> request) {
        return retrieveValue(request).map(stateSerDes::deserialize);
    }

    @Override
    public void persistState(HttpRequest<?> request, MutableHttpResponse response, State state) {
        save(request, response, stateSerDes.serialize(state));
    }
}
