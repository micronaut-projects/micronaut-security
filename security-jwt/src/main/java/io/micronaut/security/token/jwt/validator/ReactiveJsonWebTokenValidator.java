/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.token.jwt.validator;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;

/**
 * Reactive JSON Web Token (JWT) validator.
 * @author Sergio del Amo
 * @param <T> Token
 * @param <R> Request
 */
public interface ReactiveJsonWebTokenValidator<T, R> extends TokenValidator<R> {

    /**
     * Validates a Token. It should perform the following steps.
     * - Parses the Token (if encrypted it should decrypt it).
     * - Validates the Signature
     * - Validates the Claims
     * @param token The JWT Token
     * @param request An Request
     * @return Emits a single result with a JWT if the token is valid
     */
    @NonNull
    @SingleResult
    Publisher<T> validate(@NonNull String token, @Nullable R request);
}
