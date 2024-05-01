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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.*;
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

/**
 * {@link ReactiveJsonWebTokenValidator} implementation using Nimbus JOSE + JWT.
 * @author Sergio del Amo
 * @since 4.8.0
 * @param <R> The request type
 */
@Singleton
class NimbusReactiveJsonWebTokenValidator<R> extends AbstractJsonWebTokenValidator<R> implements ReactiveJsonWebTokenValidator<JWT, R> {
    private final JwtAuthenticationFactory jwtAuthenticationFactory;
    private final JsonWebTokenParser<JWT> jsonWebTokenParser;
    private final ReactiveJsonWebTokenSignatureValidator<SignedJWT> signatureValidator;

    NimbusReactiveJsonWebTokenValidator(
            List<GenericJwtClaimsValidator<R>> claimsValidators,
            List<SignatureConfiguration> imperativeSignatureConfigurations,
            List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations,
            JsonWebTokenParser<JWT> jsonWebTokenParser,
            ReactiveJsonWebTokenSignatureValidator<SignedJWT> signatureValidator,
            JwtAuthenticationFactory jwtAuthenticationFactory) {
        super(claimsValidators, imperativeSignatureConfigurations, reactiveSignatureConfigurations);
        this.jsonWebTokenParser = jsonWebTokenParser;
        this.signatureValidator = signatureValidator;
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    @Override
    @SingleResult
    public Publisher<Authentication> validateToken(String token, R request) {
        return Mono.from(validate(token, request))
                .map(jwtAuthenticationFactory::createAuthentication)
                .filter(Optional::isPresent)
                .map(Optional::get);
    }

    @NonNull
    @Override
    public Publisher<JWT> validate(@NonNull String token, @Nullable R request) {
        Optional<JWT> jwtOptional = jsonWebTokenParser.parse(token);
        if (jwtOptional.isEmpty()) {
            return Mono.empty();
        }
        JWT jwt = jwtOptional.get();
        return validateSignature(jwt)
                .filter(valid -> valid && validateClaims(jwt, request))
                .map(valid -> jwt);
    }

    private Mono<Boolean> validateSignature(JWT jwt) {
        if (jwt instanceof PlainJWT plainJWT) {
            return Mono.just(validateSignature(plainJWT));

        } else if (jwt instanceof SignedJWT signedJWT) {
            return Mono.from(signatureValidator.validateSignature(signedJWT));
        }
        return Mono.just(false);
    }
}
