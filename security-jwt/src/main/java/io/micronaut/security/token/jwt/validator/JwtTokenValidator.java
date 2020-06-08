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
package io.micronaut.security.token.jwt.validator;

import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.*;

/**
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens">Validating JWT Access Tokens</a>
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class JwtTokenValidator implements TokenValidator {

    protected final JwtAuthenticationFactory jwtAuthenticationFactory;
    private final JwtValidator validator;

    /**
     * Constructor.
     *
     * @param signatureConfigurations List of Signature configurations which are used to attempt validation.
     * @param encryptionConfigurations List of Encryption configurations which are used to attempt validation.
     * @param genericJwtClaimsValidators Generic JWT Claims validators which should be used to validate any JWT.
     * @param jwtAuthenticationFactory Utility to generate an Authentication given a JWT.
     */
    @Inject
    public JwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                             Collection<EncryptionConfiguration> encryptionConfigurations,
                             Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this(JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(genericJwtClaimsValidators)
                .build(), jwtAuthenticationFactory);
    }

    /**
     * @param validator Validates the JWT
     * @param jwtAuthenticationFactory The authentication factory
     */
    public JwtTokenValidator(JwtValidator validator,
                             JwtAuthenticationFactory jwtAuthenticationFactory) {
        this.validator = validator;
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    /***
     * @param token The token string.
     * @return Publishes {@link Authentication} based on the JWT or empty if the validation fails.
     */
    @Override
    @Deprecated
    public Publisher<Authentication> validateToken(String token) {
        return validator.validate(token)
                .flatMap(jwtAuthenticationFactory::createAuthentication)
                .map(Flowable::just)
                .orElse(Flowable.empty());
    }

}
