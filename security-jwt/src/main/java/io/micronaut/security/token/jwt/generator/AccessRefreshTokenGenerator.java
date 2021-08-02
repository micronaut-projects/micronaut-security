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
package io.micronaut.security.token.jwt.generator;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

import java.util.Map;
import java.util.Optional;

/**
 * Contract to generate {@link AccessRefreshToken} for a particular user.
 * @author Sergio del Amo
 * @since 2.0.0
 */
@DefaultImplementation(DefaultAccessRefreshTokenGenerator.class)
public interface AccessRefreshTokenGenerator {

    /**
     *
     * @param authentication User's authentication
     * @return An Optional {@link AccessRefreshToken}
     */
    @NonNull
    Optional<AccessRefreshToken> generate(@NonNull Authentication authentication);

    /**
     *
     * @param authentication User's authentication
     * @return An Optional refresh token
     */
    @NonNull
    Optional<String> generateRefreshToken(@NonNull Authentication authentication);

    /**
     *
     * @param refreshToken refresh token
     * @param oldClaims oldClaims
     * @return An Optional {@link AccessRefreshToken}
     */
    @NonNull
    Optional<AccessRefreshToken> generate(@NonNull String refreshToken, @NonNull Map<String, ?> oldClaims);

    /**
     * @param refreshToken refresh token
     * @param authentication User's authentication
     * @return An Optional refresh token
     */
    @NonNull
    Optional<AccessRefreshToken> generate(@NonNull String refreshToken, @NonNull Authentication authentication);
}
