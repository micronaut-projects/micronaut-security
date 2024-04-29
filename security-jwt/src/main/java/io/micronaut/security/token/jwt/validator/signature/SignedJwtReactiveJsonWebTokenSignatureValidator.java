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

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import java.util.List;

@Internal
public class SignedJwtReactiveJsonWebTokenSignatureValidator<T> implements ReactiveJsonWebTokenSignatureValidator<T> {
    private final List<ReactiveSignatureConfiguration<T>> signatures;

    public SignedJwtReactiveJsonWebTokenSignatureValidator(List<ReactiveSignatureConfiguration<T>> signatures) {
        this.signatures = signatures;
    }

    @Override
    @SingleResult
    public Publisher<Boolean> validateSignature(T signedToken) {
        return Flux.fromIterable(signatures)
                .flatMap(signatureConfiguration -> signatureConfiguration.verify(signedToken))
                .filter(Boolean::booleanValue)
                .next();
    }
}
