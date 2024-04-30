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
package io.micronaut.security.token.jwt.validator.signature;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import org.reactivestreams.Publisher;

/**
 * Reactive API to validates the signature of a JSON Web Token.
 * @author Sergio del Amo
 * @since 4.8.0
 * @param <T> The Signed Token
 */
@FunctionalInterface
public interface ReactiveJsonWebTokenSignatureValidator<T> {

    /**
     *
     * @param signedToken signed token
     * @return A publisher with a single result with a true boolean if the token signature can be verified.
     */
    @SingleResult
    @NonNull
    Publisher<Boolean> validateSignature(@NonNull T signedToken);
}
