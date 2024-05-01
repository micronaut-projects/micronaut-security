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
package io.micronaut.security.token.jwt.signature;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import org.reactivestreams.Publisher;

/**
 * Reactive Signature Configuration.
 * @author Sergio del Amo
 * @param <T> Token
 * @since 4.8.0
 */
public interface ReactiveSignatureConfiguration<T> {
    /**
     * Verify a signed token.
     *
     * @param token the signed token
     * @return whether the signed token is verified
     */
    @SingleResult
    @NonNull
    Publisher<Boolean> verify(@NonNull T token);
}
