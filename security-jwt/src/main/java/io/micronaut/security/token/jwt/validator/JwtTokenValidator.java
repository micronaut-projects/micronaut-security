/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/validating-jwt-access-tokens">Validating JWT Access Tokens</a>
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class JwtTokenValidator implements TokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenValidator.class);

    protected final List<SignatureConfiguration> signatureConfigurations = new ArrayList<>();
    protected final List<EncryptionConfiguration> encryptionConfigurations = new ArrayList<>();
    protected final List<GenericJwtClaimsValidator> genericJwtClaimsValidators = new ArrayList<>();
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
        this.signatureConfigurations.addAll(signatureConfigurations);
        this.encryptionConfigurations.addAll(encryptionConfigurations);
        this.genericJwtClaimsValidators.addAll(genericJwtClaimsValidators);
        this.jwtAuthenticationFactory = jwtAuthenticationFactory;
    }

    /**
     *
     * Deprecated Constructor.
     *
     * @deprecated Use {@link JwtTokenValidator#JwtTokenValidator(Collection, Collection, Collection, JwtAuthenticationFactory)} instead.
     * @param signatureConfigurations List of Signature configurations which are used to attempt validation.
     * @param encryptionConfigurations List of Encryption configurations which are used to attempt validation.
     */
    @Deprecated
    public JwtTokenValidator(Collection<SignatureConfiguration> signatureConfigurations,
                             Collection<EncryptionConfiguration> encryptionConfigurations) {
        this(signatureConfigurations,
                encryptionConfigurations,
                Collections.singleton(new ExpirationJwtClaimsValidator()),
                new DefaultJwtAuthenticationFactory());
    }



    /**
     * Validates the Signature of a plain JWT.
     * @param jwt a JWT Token
     * @return empty if signature configurations exists, Optional.of(jwt) if no signature configuration is available.
     */
    public Optional<JWT> validatePlainJWTSignature(JWT jwt) {
        return JwtTokenValidatorUtils.validatePlainJWTSignature(jwt, signatureConfigurations);
    }

    /**
     *
     * Validates a Signed JWT signature.
     *
     * @param signedJWT a Signed JWT Token
     * @return empty if signature validation fails
     */
    public  Optional<JWT> validateSignedJWTSignature(SignedJWT signedJWT) {
        return JwtTokenValidatorUtils.validateSignedJWTSignature(signedJWT, signatureConfigurations);
    }

    /**
     * Verifies the provided claims with the provided validators.
     * @deprecated use {@link io.micronaut.security.token.jwt.validator.JwtTokenValidatorUtils#verifyClaims(io.micronaut.security.token.jwt.generator.claims.JwtClaims, Collection)} instead.
     * @param jwtClaimsSet JWT Claims
     * @param claimsValidators The claims validators
     * @return Whether the JWT claims pass every validation.
     */
    @Deprecated
    public boolean verifyClaims(JWTClaimsSet jwtClaimsSet, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return JwtTokenValidatorUtils.verifyClaims(new JwtClaimsSetAdapter(jwtClaimsSet), claimsValidators);
    }

    /**
     *
     * Validates a encrypted JWT Signature.
     *
     * @deprecated use {@link io.micronaut.security.token.jwt.validator.JwtTokenValidatorUtils#validateEncryptedJWTSignature(EncryptedJWT, String, List, List)}
     *
     * @param encryptedJWT a encrytped JWT Token
     * @param token the JWT token as String
     * @return empty if signature validation fails
     */
    @Deprecated
    public Optional<JWT> validateEncryptedJWTSignature(EncryptedJWT encryptedJWT, String token) {
        return JwtTokenValidatorUtils.validateEncryptedJWTSignature(encryptedJWT,
                token,
                signatureConfigurations,
                encryptionConfigurations);
    }

    /**
     *
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
     */
    public Optional<Authentication> authenticationIfValidJwtSignatureAndClaims(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        Optional<JWT> jwt = validateJwtSignatureAndClaims(token, claimsValidators);
        if (jwt.isPresent()) {
            return jwtAuthenticationFactory.createAuthentication(jwt.get());
        }
        return Optional.empty();

    }

    /**
     * Validates JWT signature and Claims.
     * @param token A JWT token
     * @return empty if signature or claims verification failed, JWT otherwise.
     */
    public Optional<JWT> validateJwtSignatureAndClaims(String token) {
        return validateJwtSignatureAndClaims(token, genericJwtClaimsValidators);
    }

    /**
     *
     * @param token A JWT token
     * @return true if signature or claims verification passed
     */
    public boolean validate(String token) {
        return validateJwtSignatureAndClaims(token).isPresent();
    }

    /**
     *
     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @return true if signature or claims verification passed
     */
    public boolean validate(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return validateJwtSignatureAndClaims(token, claimsValidators).isPresent();
    }

    /**
     * Validates JWT signature and Claims.
     *
     * @deprecated use {@link io.micronaut.security.token.jwt.validator.JwtTokenValidatorUtils#validateJwtSignatureAndClaims(String, Collection, List, List)} instead.
     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @return empty if signature or claims verification failed, JWT otherwise.
     */
    @Deprecated
    public Optional<JWT> validateJwtSignatureAndClaims(String token, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return JwtTokenValidatorUtils.validateJwtSignatureAndClaims(token,
                claimsValidators,
                signatureConfigurations,
                encryptionConfigurations);
    }

    /**
     * Returns a JWT if the signature could be verified.
     *
     * @deprecated use {@link io.micronaut.security.token.jwt.validator.JwtTokenValidatorUtils#parseJwtIfValidSignature(String, List, List)}
     * @param token a JWT token
     * @return Empty if JWT signature verification failed or JWT if valid signature.
     */
    @Deprecated
    public Optional<JWT> parseJwtIfValidSignature(String token) {
        return JwtTokenValidatorUtils.parseJwtIfValidSignature(token,
                signatureConfigurations,
                encryptionConfigurations);
    }


    /**
     *
     * @return List of Signature configurations which are used to attempt validation.
     */
    public List<SignatureConfiguration> getSignatureConfigurations() {
        return signatureConfigurations;
    }

    /**
     *
     * @return List of Encryption configurations which are used to attempt validation.
     */
    public List<EncryptionConfiguration> getEncryptionConfigurations() {
        return encryptionConfigurations;
    }

    /**
     *
     * @return Generic JWT Claims validators which should be used to validate any JWT.
     */
    public List<GenericJwtClaimsValidator> getGenericJwtClaimsValidators() {
        return genericJwtClaimsValidators;
    }
}
