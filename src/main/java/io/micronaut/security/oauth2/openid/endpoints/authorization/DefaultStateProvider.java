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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.http.HttpAttributes;
import io.micronaut.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Singleton;
import java.io.IOException;

/**
 * A default state provider that stores the original
 * request URI to redirect back to after authentication.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
@Singleton
public class DefaultStateProvider implements StateProvider {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultStateProvider.class);

    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper To serialize the state
     */
    public DefaultStateProvider(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Nullable
    @Override
    public String generateState(HttpRequest<?> request) {
        boolean unauthorized = !request.getAttribute(HttpAttributes.PRINCIPAL).isPresent();
        Object state = buildState(request, unauthorized);
        if (state != null) {
            return serializeState(state);
        } else {
            return null;
        }
    }

    @Override
    public Object deserializeState(String state) {
        try {
            return objectMapper.readValue(state, DefaultState.class);
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to deserialize the authorization request state", e);
            }
        }
        return null;
    }

    /**
     * Serializes the state into a string for sending with the authorization redirect.
     *
     * @param state The state object
     * @return The serialized state
     */
    @Nullable
    protected String serializeState(Object state) {
        try {
            return objectMapper.writeValueAsString(state);
        } catch (JsonProcessingException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to serialize the authorization request state to JSON", e);
            }
        }
        return null;
    }

    /**
     * Creates the state object to be sent with the authorization redirect.
     *
     * @param request The originating request
     * @param unauthorized whether the request was flagged as unauthorized
     * @return The state object
     */
    @Nullable
    protected Object buildState(HttpRequest<?> request, boolean unauthorized) {
        DefaultState state = new DefaultState();
        if (unauthorized) {
            state.setOriginalUri(request.getUri());
        }
        return state;
    }
}
