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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.io.IOException;

/**
 * Jackson based implementation for state serdes.
 *
 * @author James Kleeh
 * @since 1.0.0
 */
@Singleton
public class JacksonStateSerDes implements StateSerDes {

    private static final Logger LOG = LoggerFactory.getLogger(JacksonStateSerDes.class);

    private final ObjectMapper objectMapper;

    /**
     * @param objectMapper To serialize/de-serialize the state
     */
    public JacksonStateSerDes(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public State deserialize(String state) {
        try {
            return objectMapper.readValue(state, DefaultState.class);
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to deserialize the authorization request state", e);
            }
        }
        return null;
    }

    @Override
    public String serialize(State state) {
        try {
            return objectMapper.writeValueAsString(state);
        } catch (JsonProcessingException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to serialize the authorization request state to JSON", e);
            }
        }
        return null;
    }

}
