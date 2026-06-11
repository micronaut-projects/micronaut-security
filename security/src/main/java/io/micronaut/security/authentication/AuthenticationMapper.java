/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.authentication;

import org.jspecify.annotations.NonNull;

import java.io.IOException;

/**
 * Maps a serialized representation to an {@link Authentication}.
 * <p>
 * For example, an implementation can bind from a JSON string such as:
 * <pre>{@code
 * {"name":"sergio","attributes":{"family_name":"del Amo","given_name":"Sergio","roles":["ROLE_USER"]}}
 * }</pre>
 * to an {@link Authentication} object.
 *
 * @since 5.1.0
 */
@FunctionalInterface
public interface AuthenticationMapper {
    /**
     * Reads an {@link Authentication} from the supplied input.
     *
     * @param input The serialized authentication representation
     * @return The authentication representation
     * @throws IOException if the input cannot be deserialized to {@link Authentication}.
     */
    @NonNull Authentication read(@NonNull String input) throws IOException;
}
