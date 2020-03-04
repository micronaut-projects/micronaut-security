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

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenValidator.class);

    protected final List<SignatureConfiguration> signatureConfigurations;
    protected final List<EncryptionConfiguration> encryptionConfigurations;
    protected final List<GenericJwtClaimsValidator> genericJwtClaimsValidators;
    protected final JwtAuthenticationFactory jwtAuthenticationFactory;

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
        this.signatureConfigurations = Collections.unmodifiableList(new ArrayList<>(signatureConfigurations));
        this.encryptionConfigurations = Collections.unmodifiableList(new ArrayList<>(encryptionConfigurations));
        this.genericJwtClaimsValidators = Collections.unmodifiableList(new ArrayList<>(genericJwtClaimsValidators));
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    /**
     * Validates the Signature of a plain JWT.
     * @param jwt a JWT Token
     * @return empty if signature configurations exists, Optional.of(jwt) if no signature configuration is available.
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<JWT> validatePlainJWTSignature(JWT jwt) {
        return JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .build()
                .validate(jwt);
    }

    /**
     *
     * Validates a Signed JWT signature.
     *
     * @param signedJWT a Signed JWT Token
     * @return empty if signature validation fails
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public  Optional<JWT> validateSignedJWTSignature(SignedJWT signedJWT) {
        return JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .build()
                .validate(signedJWT);
    }

    /**
     * Verifies the provided claims with the provided validators.
     * @param jwtClaimsSet JWT Claims
     * @param claimsValidators The claims validators
     * @return Whether the JWT claims pass every validation.
     * @deprecated No replacement. Implement the logic in your own codebase
     */
    @Deprecated
    public boolean verifyClaims(JWTClaimsSet jwtClaimsSet, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return JwtTokenValidatorUtils.verifyClaims(new JwtClaimsSetAdapter(jwtClaimsSet), claimsValidators);
    }

    /**
     *
     * Validates a encrypted JWT Signature.
     *
     *
     * @param encryptedJWT a encrytped JWT Token
     * @param token the JWT token as String
     * @return empty if signature validation fails
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<JWT> validateEncryptedJWTSignature(EncryptedJWT encryptedJWT, String token) {
        return JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .build()
                .validate(encryptedJWT);
    }

    /***
     * @param token The token string.
     * @return Publishes {@link Authentication} based on the JWT or empty if the validation fails.
     */
    @Override
    public Publisher<Authentication> validateToken(String token) {
        Optional<Authentication> authentication = authenticationIfValidJwtSignatureAndClaims(token, genericJwtClaimsValidators);
        if (authentication.isPresent()) {
            return Flowable.just(authentication.get());
        }
        return Flowable.empty();
    }

    /**
     * Authentication if JWT has valid signature and claims are verified.
     *
     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @return empty if signature or claims verification failed, An Authentication otherwise.
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<Authentication> authenticationIfValidJwtSignatureAndClaims(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        Optional<JWT> jwt = JwtTokenValidatorUtils.validateJwtSignatureAndClaims(token, claimsValidators,
                signatureConfigurations,
                encryptionConfigurations);
        if (jwt.isPresent()) {
            return jwtAuthenticationFactory.createAuthentication(jwt.get());
        }
        return Optional.empty();

    }

    /**
     * Validates JWT signature and Claims.
     * @param token A JWT token
     * @return empty if signature or claims verification failed, JWT otherwise.
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<JWT> validateJwtSignatureAndClaims(String token) {
        return JwtTokenValidatorUtils.validateJwtSignatureAndClaims(token,
                genericJwtClaimsValidators,
                signatureConfigurations,
                encryptionConfigurations);
    }

    /**
     *
     * @param token A JWT token
     * @return true if signature or claims verification passed
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public boolean validate(String token) {
        return validateJwtSignatureAndClaims(token).isPresent();
    }

    /**
     *
     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @return true if signature or claims verification passed
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public boolean validate(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return validateJwtSignatureAndClaims(token, claimsValidators).isPresent();
    }

    /**
     * Validates JWT signature and Claims.

     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @return empty if signature or claims verification failed, JWT otherwise.
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<JWT> validateJwtSignatureAndClaims(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .withClaimValidators(claimsValidators)
                .build()
                .validate(token);
    }

    /**
     * Returns a JWT if the signature could be verified.
     *
     * @param token a JWT token
     * @return Empty if JWT signature verification failed or JWT if valid signature.
     * @deprecated Use {@link JwtValidator} instead.
     */
    @Deprecated
    public Optional<JWT> parseJwtIfValidSignature(String token) {
        return JwtValidator.builder()
                .withSignatures(signatureConfigurations)
                .withEncryptions(encryptionConfigurations)
                .build()
                .validate(token);
    }


    /**
     * @return List of Signature configurations which are used to attempt validation.
     * @deprecated Will be removed in a future version
     */
    @Deprecated
    public List<SignatureConfiguration> getSignatureConfigurations() {
        return signatureConfigurations;
    }

    /**
     * @return List of Encryption configurations which are used to attempt validation.
     * @deprecated Will be removed in a future version
     */
    @Deprecated
    public List<EncryptionConfiguration> getEncryptionConfigurations() {
        return encryptionConfigurations;
    }

    /**
     * @return Generic JWT Claims validators which should be used to validate any JWT.
     * @deprecated Will be removed in a future version
     */
    @Deprecated
    public List<GenericJwtClaimsValidator> getGenericJwtClaimsValidators() {
        return genericJwtClaimsValidators;
    }

}
