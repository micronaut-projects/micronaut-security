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
package io.micronaut.security.token.validator;

import io.micronaut.core.annotation.NonNull;

import java.util.Optional;

/**
 * Responsible for validating a refresh token
 * is in a valid format. This logic is separate from determining
 * if the refresh token has been revoked or otherwise not
 * present in the persistence layer.
 *
 * @author James Kleeh
 * @since 2.0.0
 */
@FunctionalInterface
public interface RefreshTokenValidator {

    /**
     * @param refreshToken The refresh token
     * @return The validated token wrapped in an Optional or {@literal Optional#empty()} if the supplied token is invalid.
     */
    @NonNull
    Optional<String> validate(@NonNull String refreshToken);
}
