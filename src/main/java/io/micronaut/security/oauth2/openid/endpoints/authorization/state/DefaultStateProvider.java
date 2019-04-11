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

package io.micronaut.security.oauth2.openid.endpoints.authorization.state;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.validation.StatePersistence;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * A default state provider that stores the original
 * request URI to redirect back to after authentication.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
@Singleton
public class DefaultStateProvider implements StateProvider {

    private final StateSerDes stateSerDes;
    @Nullable
    private final StatePersistence statePersistence;

    /**
     * @param stateSerDes To serialize the state
     */
    public DefaultStateProvider(StateSerDes stateSerDes, @Nullable StatePersistence statePersistence) {
        this.stateSerDes = stateSerDes;
        this.statePersistence = statePersistence;
    }

    @Nullable
    @Override
    public String generateState(HttpRequest<?> request) {
        Optional<HttpStatus> rejectedStatus = request.getAttribute(SecurityFilter.REJECTION, HttpStatus.class);
        boolean unauthorized = rejectedStatus.isPresent() && rejectedStatus.get().equals(HttpStatus.UNAUTHORIZED);
        DefaultState state = new DefaultState();
        if (unauthorized) {
            state.setOriginalUri(request.getUri());
        }
        if (statePersistence != null) {
            statePersistence.persistState(request, state);
        }
        return stateSerDes.serialize(state);
    }

}
