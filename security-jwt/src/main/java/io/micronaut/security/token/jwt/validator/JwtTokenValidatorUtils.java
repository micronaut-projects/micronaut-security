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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.text.ParseException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Utility methods to validate JWT signatures and claims.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 * @deprecated Use {@link JwtValidator} instead
 */
@Deprecated
public final class JwtTokenValidatorUtils {

    private static final Logger LOG = LoggerFactory.getLogger(JwtTokenValidatorUtils.class);

    private JwtTokenValidatorUtils() {

    }

    /**
     * Validates the Signature of a plain JWT.
     * @param jwt a JWT Token
     * @param signatureConfigurations The signature configurations
     * @return empty if signature configurations exists, Optional.of(jwt) if no signature configuration is available.
     */
    public static Optional<JWT> validatePlainJWTSignature(JWT jwt,
                                                          List<SignatureConfiguration> signatureConfigurations) {
        if (signatureConfigurations.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT is not signed and no signature configurations -> verified");
            }
            return Optional.of(jwt);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A non-signed JWT cannot be accepted as signature configurations have been defined");
            }
            return Optional.empty();
        }
    }

    /**
     *
     * Validates a Signed JWT signature.
     *
     * @param signedJWT a Signed JWT Token
     * @param signatureConfigurations The signature configurations
     * @return empty if signature validation fails
     */
    public static Optional<JWT> validateSignedJWTSignature(SignedJWT signedJWT,
                                                           List<SignatureConfiguration> signatureConfigurations) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("JWT is signed");
        }

        final JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
        for (final SignatureConfiguration config : signatureConfigurations) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Using signature configuration: {}", config.toString());
            }
            try {
                if (config.verify(signedJWT)) {
                    return Optional.of(signedJWT);
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("JWT Signature verification failed: {}", signedJWT.getParsedString());
                    }
                }
            } catch (final JOSEException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verification fails with signature configuration: {}, passing to the next one", config);
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No signature algorithm found for JWT: {}", signedJWT.getParsedString());
        }
        return Optional.empty();
    }

    /**
     * Verifies the provided claims with the provided validators.
     *
     * @param claims JWT Claims
     * @param claimsValidators The claims validators
     * @return Whether the JWT claims pass every validation.
     */
    public static boolean verifyClaims(JwtClaims claims, Collection<? extends JwtClaimsValidator> claimsValidators) {
        return claimsValidators.stream()
                .allMatch(jwtClaimsValidator -> jwtClaimsValidator.validate(claims));
    }

    /**
     *
     * Validates a encrypted JWT Signature.
     *
     * @param encryptedJWT a encrytped JWT Token
     * @param token the JWT token as String
     * @param signatureConfigurations The signature configurations
     * @param encryptionConfigurations The encryption configurations
     * @return empty if signature validation fails
     */
    public static Optional<JWT> validateEncryptedJWTSignature(@Nonnull EncryptedJWT encryptedJWT,
                                                       @Nonnull String token,
                                                       @Nonnull List<SignatureConfiguration> signatureConfigurations,
                                                       @Nonnull List<EncryptionConfiguration> encryptionConfigurations) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("JWT is encrypted");
        }

        final JWEHeader header = encryptedJWT.getHeader();
        final JWEAlgorithm algorithm = header.getAlgorithm();
        final EncryptionMethod method = header.getEncryptionMethod();
        for (final EncryptionConfiguration config : encryptionConfigurations) {
            if (config.supports(algorithm, method)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Using encryption configuration: {}", config.toString());
                }
                try {
                    config.decrypt(encryptedJWT);
                    SignedJWT signedJWT = encryptedJWT.getPayload().toSignedJWT();
                    if (signedJWT == null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("encrypted JWT could couldn't be converted to a signed JWT.");
                        }
                        return Optional.empty();
                    }
                    return validateSignedJWTSignature(signedJWT, signatureConfigurations);

                } catch (final JOSEException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Decryption fails with encryption configuration: {}, passing to the next one", config.toString());
                    }
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("No encryption algorithm found for JWT: {}", token);
        }
        return Optional.empty();
    }

    /**
     * Validates JWT signature and Claims.
     *
     * @param token A JWT token
     * @param claimsValidators a Collection of claims Validators.
     * @param signatureConfigurations The signature configurations
     * @param encryptionConfigurations The encryption configurations
     * @return empty if signature or claims verification failed, JWT otherwise.
     */
    public static Optional<JWT> validateJwtSignatureAndClaims(String token,
                                                       Collection<? extends JwtClaimsValidator> claimsValidators,
                                                       List<SignatureConfiguration> signatureConfigurations,
                                                       List<EncryptionConfiguration> encryptionConfigurations) {
        Optional<JWT> jwt = parseJwtIfValidSignature(token, signatureConfigurations, encryptionConfigurations);
        if (jwt.isPresent()) {
            try {
                if (verifyClaims(new JwtClaimsSetAdapter(jwt.get().getJWTClaimsSet()), claimsValidators)) {
                    return jwt;
                }
            } catch (ParseException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("ParseException creating authentication", e.getMessage());
                }
            }
        }
        return Optional.empty();
    }


    /**
     * @param token A JWT token string
     * @param signatureConfigurations The signature configurations
     * @param encryptionConfigurations The encryption configurations
     * @return A JWT if validation succeeded
     */
    public static Optional<JWT> parseJwtIfValidSignature(String token, List<SignatureConfiguration> signatureConfigurations, List<EncryptionConfiguration> encryptionConfigurations) {
        try {
            JWT jwt = JWTParser.parse(token);

            if (jwt instanceof PlainJWT) {
                return validatePlainJWTSignature(jwt, signatureConfigurations);

            } else if (jwt instanceof EncryptedJWT) {
                final EncryptedJWT encryptedJWT = (EncryptedJWT) jwt;
                return validateEncryptedJWTSignature(encryptedJWT, token, signatureConfigurations, encryptionConfigurations);

            } else if (jwt instanceof SignedJWT) {
                final SignedJWT signedJWT = (SignedJWT) jwt;
                return validateSignedJWTSignature(signedJWT, signatureConfigurations);
            }

        } catch (final ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Cannot decrypt / verify JWT: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
}
