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

/**
 * API to validate the signature of a JSON Web Token with beans of type {@link io.micronaut.security.token.jwt.signature.SignatureConfiguration}.
 * @author Sergio del Amo
 * @since 4.8.0
 * @param <T> Signed Token
 */
@FunctionalInterface
public interface JsonWebTokenSignatureValidator<T> {

    /**
     *
     * @param signedToken signed token
     * @return true if the token signature can be verified.
     */
    boolean validateSignature(@NonNull T signedToken);
}
