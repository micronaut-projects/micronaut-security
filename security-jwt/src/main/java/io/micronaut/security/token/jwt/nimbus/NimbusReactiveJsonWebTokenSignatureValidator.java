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
package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;

@Internal
@Singleton
class NimbusReactiveJsonWebTokenSignatureValidator implements ReactiveJsonWebTokenSignatureValidator<SignedJWT> {
    private final List<ReactiveSignatureConfiguration<SignedJWT>> signatures;

    public NimbusReactiveJsonWebTokenSignatureValidator(List<SignatureConfiguration> signatureConfigurations,
                                                        List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations) {
        this.signatures = signatures(signatureConfigurations, reactiveSignatureConfigurations);
    }

    @Override
    @SingleResult
    public Publisher<Boolean> validateSignature(@NonNull SignedJWT signedToken) {
        return Flux.fromIterable(signatures)
                .flatMap(signatureConfiguration -> signatureConfiguration.verify(signedToken))
                .filter(Boolean::booleanValue)
                .next();
    }

    private static List<ReactiveSignatureConfiguration<SignedJWT>> signatures(List<SignatureConfiguration> signatureConfigurations,
                                                                       List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations) {
        List<ReactiveSignatureConfiguration<SignedJWT>> signatures = new ArrayList<>();
        signatures.addAll(signatureConfigurations.stream().map(NimbusReactiveSignatureConfigurationAdapter::new).toList());
        signatures.addAll(reactiveSignatureConfigurations);
        OrderUtil.sort(signatures);
        return signatures;
    }
}
