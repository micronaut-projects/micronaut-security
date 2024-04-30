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

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.validator.*;
import io.micronaut.security.token.jwt.validator.signature.JsonWebTokenSignatureValidator;
import jakarta.inject.Singleton;

import java.util.List;
import java.util.Optional;

/**
 * {@link JsonWebTokenValidator} implementation using Nimbus JOSE + JWT.
 * @author Sergio del Amo
 * @since 4.8.0
 */
@Singleton
class NimbusJsonWebTokenValidator<R> extends AbstractJsonWebTokenValidator<R> implements JsonWebTokenValidator<JWT, R> {
    private final JsonWebTokenParser<JWT> jsonWebTokenParser;
    private final JsonWebTokenSignatureValidator<SignedJWT> signatureValidator;

    NimbusJsonWebTokenValidator(
            List<GenericJwtClaimsValidator<R>> claimsValidators,
            List<SignatureConfiguration> imperativeSignatureConfigurations,
            List<ReactiveSignatureConfiguration<SignedJWT>> reactiveSignatureConfigurations,
            JsonWebTokenParser<JWT> jsonWebTokenParser,
            JsonWebTokenSignatureValidator<SignedJWT> signatureValidator) {
        super(claimsValidators, imperativeSignatureConfigurations, reactiveSignatureConfigurations);
        this.jsonWebTokenParser = jsonWebTokenParser;
        this.signatureValidator = signatureValidator;
    }

    @NonNull
    @Override
    public Optional<JWT> validate(@NonNull String token, @Nullable R request) {
        Optional<JWT> jwtOptional = jsonWebTokenParser.parse(token);
        if (jwtOptional.isEmpty()) {
            return Optional.empty();
        }
        JWT jwt = jwtOptional.get();
        if (!validateSignature(jwt)) {
            return Optional.empty();
        }
        if (!validateClaims(jwt, request)) {
            return Optional.empty();
        }
        return Optional.of(jwt);
    }

    private boolean validateSignature(JWT jwt) {
        if (jwt instanceof PlainJWT plainJWT) {
            return validateSignature(plainJWT);

        } else if (jwt instanceof SignedJWT signedJWT) {
            return signatureValidator.validateSignature(signedJWT);
        }
        return false;
    }
}
