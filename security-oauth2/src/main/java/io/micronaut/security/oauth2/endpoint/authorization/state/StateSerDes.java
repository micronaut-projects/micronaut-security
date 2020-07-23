/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.state;

import io.micronaut.context.annotation.DefaultImplementation;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Responsible for serialization and de-serialization of the state.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@DefaultImplementation(JacksonStateSerDes.class)
public interface StateSerDes {

    /**
     * De-serializes the state string into a {@link State} object.
     *
     * @param state The state string
     * @return The state, or null if the de-serialization encountered an error.
     */
    @Nullable
    State deserialize(String state);

    /**
     * Serializes the state into a string for sending with the authorization redirect.
     *
     * @param state The state object
     * @return The serialized state, or null if the serialization encountered an error.
     */
    @Nullable
    String serialize(State state);
}
