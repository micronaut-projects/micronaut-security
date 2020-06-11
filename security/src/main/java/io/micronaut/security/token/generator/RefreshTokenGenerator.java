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
package io.micronaut.security.token.generator;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.security.authentication.Authentication;

import java.util.Optional;

/**
 * Responsible for generating refresh tokens. This class assumes the internal
 * value of the token will be transformed in some way before being sent to
 * the client.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
public interface RefreshTokenGenerator {

    /**
     * @param authentication Authentication
     * @return The internal value that will persisted.
     */
    @NonNull
    String createKey(@NonNull Authentication authentication);

    /**
     * @param authentication Authentication
     * @param token The internal value
     * @return The refresh token
     */
    @NonNull
    Optional<String> generate(@NonNull Authentication authentication, @NonNull String token);

}
