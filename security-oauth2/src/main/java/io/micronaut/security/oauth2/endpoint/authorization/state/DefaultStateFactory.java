/*
 * Copyright 2017-2020 original authors
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

package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.uri.UriBuilder;
import io.micronaut.security.filters.SecurityFilter;
import io.micronaut.security.oauth2.endpoint.authorization.request.AuthorizationRequest;
import io.micronaut.security.oauth2.endpoint.authorization.state.persistence.StatePersistence;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.util.Optional;

/**
 * A default state provider that stores the original
 * request URI to redirect back to after authentication.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
@Requires(beans = StatePersistence.class)
public class DefaultStateFactory implements StateFactory {

    private final StateSerDes stateSerDes;
    private final StatePersistence statePersistence;

    /**
     * @param stateSerDes To serialize the state
     * @param statePersistence A state persistence
     */
    public DefaultStateFactory(StateSerDes stateSerDes, StatePersistence statePersistence) {
        this.stateSerDes = stateSerDes;
        this.statePersistence = statePersistence;
    }

    @SuppressWarnings("rawtypes")
    @Nullable
    @Override
    public String buildState(HttpRequest<?> request, MutableHttpResponse response) {
        return buildState(request, response, null);
    }

    @SuppressWarnings("rawtypes")
    @Nullable
    @Override
    public String buildState(HttpRequest<?> request, MutableHttpResponse response, @Nullable AuthorizationRequest authorizationRequest) {
        Optional<HttpStatus> rejectedStatus = request.getAttribute(SecurityFilter.REJECTION, HttpStatus.class);
        boolean unauthorized = rejectedStatus.filter(status -> status.equals(HttpStatus.UNAUTHORIZED)).isPresent();
        DefaultState state = new DefaultState();
        if (unauthorized) {
            state.setOriginalUri(request.getUri());
        }
        if (authorizationRequest != null && authorizationRequest.getRedirectUri().isPresent()) {
            state.setRedirectUri(UriBuilder.of(authorizationRequest.getRedirectUri().get()).build());
        }
        statePersistence.persistState(request, response, state);
        return stateSerDes.serialize(state);
    }
}
