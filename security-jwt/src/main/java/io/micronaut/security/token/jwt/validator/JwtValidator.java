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

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.*;

/**
 * A builder style class for validating JWT tokens against any number of provided
 * encryption or signature configurations and any claim validators.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
public final class JwtValidator {

    private static final Logger LOG = LoggerFactory.getLogger(JwtValidator.class);

    private final List<SignatureConfiguration> signatures;
    private final List<EncryptionConfiguration> encryptions;
    private final List<JwtClaimsValidator> claimsValidators;

    private JwtValidator(List<SignatureConfiguration> signatures, List<EncryptionConfiguration> encryptions, List<JwtClaimsValidator> claimsValidators) {
        this.signatures = signatures;
        this.encryptions = encryptions;
        this.claimsValidators = claimsValidators;
    }

    /**
     * Validates the supplied token with any configurations and claim validators present.
     *
     * @param token The JWT string
     * @return An optional JWT token if validation succeeds
     */
    public Optional<JWT> validate(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            return validate(jwt);
        } catch (final ParseException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Failed to parse JWT: {}", e.getMessage());
            }
            return Optional.empty();
        }
    }

    /**
     * Validates the supplied token with any configurations and claim validators present.
     *
     * @param token The JWT token
     * @return An optional JWT token if validation succeeds
     */
    public Optional<JWT> validate(JWT token) {
        Optional<JWT> validationResult;
        if (token instanceof PlainJWT) {
            validationResult = validate((PlainJWT) token);
        } else if (token instanceof EncryptedJWT) {
            validationResult = validate((EncryptedJWT) token);
        } else if (token instanceof SignedJWT) {
            validationResult = validate((SignedJWT) token);
        } else {
            validationResult = Optional.empty();
        }
        if (claimsValidators.isEmpty()) {
            return validationResult;
        } else {
            return validationResult.filter(jwt -> {
                try {
                    JwtClaims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
                    return claimsValidators.stream().allMatch(validator -> validator.validate(claims));
                } catch (ParseException e) {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("Failed to retrieve the claims set", e);
                    }
                    return false;
                }
            });
        }
    }

    private Optional<JWT> validate(PlainJWT jwt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating plain JWT");
        }
        if (signatures.isEmpty()) {
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

    private Optional<JWT> validate(EncryptedJWT jwt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating encrypted JWT");
        }

        final JWEHeader header = jwt.getHeader();

        List<EncryptionConfiguration> sortedConfigs = new ArrayList<>(encryptions);
        sortedConfigs.sort(comparator(header));

        for (EncryptionConfiguration config: sortedConfigs) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using encryption configuration: {}", config.toString());
            }
            try {
                config.decrypt(jwt);
                SignedJWT signedJWT = jwt.getPayload().toSignedJWT();
                if (signedJWT == null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Encrypted JWT couldn't be converted to a signed JWT.");
                    }
                    return Optional.empty();
                }
                return validate(signedJWT);
            } catch (final JOSEException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Decryption fails with encryption configuration: {}, passing to the next one", config.toString());
                }
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private Optional<JWT> validate(SignedJWT jwt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating signed JWT");
        }

        final JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();

        List<SignatureConfiguration> sortedConfigs = new ArrayList<>(signatures);
        sortedConfigs.sort(comparator(algorithm));

        for (SignatureConfiguration config: sortedConfigs) {
            try {
                boolean verified = config.verify(jwt);
                if (!verified) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("JWT Signature verification failed: {}", jwt.getParsedString());
                    }
                } else {
                    return Optional.of(jwt);
                }
            } catch (final JOSEException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verification failed with signature configuration: {}, passing to the next one", config);
                }
            }
        }
        return Optional.empty();
    }

    private static Comparator<SignatureConfiguration> comparator(JWSAlgorithm algorithm) {
        return (sig, otherSig) -> {
            boolean supports = sig.supports(algorithm);
            boolean otherSupports = otherSig.supports(algorithm);
            if (supports == otherSupports) {
                return 0;
            } else if (supports) {
                return -1;
            } else {
                return 1;
            }
        };
    }

    private static Comparator<EncryptionConfiguration> comparator(JWEHeader header) {
        final JWEAlgorithm algorithm = header.getAlgorithm();
        final EncryptionMethod method = header.getEncryptionMethod();
        return (sig, otherSig) -> {
            boolean supports = sig.supports(algorithm, method);
            boolean otherSupports = otherSig.supports(algorithm, method);
            if (supports == otherSupports) {
                return 0;
            } else if (supports) {
                return -1;
            } else {
                return 1;
            }
        };
    }

    /**
     * @return A new JWT validator builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder for {@link JwtValidator}.
     */
    public static final class Builder {

        private List<SignatureConfiguration> signatures = new ArrayList<>();
        private List<EncryptionConfiguration> encryptions = new ArrayList<>();
        private List<JwtClaimsValidator> claimsValidators = new ArrayList<>();

        private Builder() { }

        /**
         * Replaces any existing configurations with the ones supplied.
         *
         * @param signatureConfigurations The signature configurations to validate with
         * @return The builder
         */
        public Builder withSignatures(SignatureConfiguration... signatureConfigurations) {
            signatures = Arrays.asList(signatureConfigurations);
            return this;
        }

        /**
         * Replaces any existing configurations with the ones supplied.
         *
         * @param signatureConfigurations The signature configurations to validate with
         * @return The builder
         */
        public Builder withSignatures(Collection<? extends SignatureConfiguration> signatureConfigurations) {
            signatures = new ArrayList<>(signatureConfigurations);
            return this;
        }

        /**
         * Replaces any existing configurations with the ones supplied.
         *
         * @param encryptionConfigurations The encryption configurations to validate with
         * @return The builder
         */
        public Builder withEncryptions(EncryptionConfiguration... encryptionConfigurations) {
            encryptions = Arrays.asList(encryptionConfigurations);
            return this;
        }

        /**
         * Replaces any existing configurations with the ones supplied.
         *
         * @param encryptionConfigurations The encryption configurations to validate with
         * @return The builder
         */
        public Builder withEncryptions(Collection<? extends EncryptionConfiguration> encryptionConfigurations) {
            encryptions = new ArrayList<>(encryptionConfigurations);
            return this;
        }

        /**
         * Replaces any existing claim validators with the ones supplied.
         *
         * @param jwtClaimsValidators The claims validators to use
         * @return The builder
         */
        public Builder withClaimValidators(JwtClaimsValidator... jwtClaimsValidators) {
            claimsValidators = Arrays.asList(jwtClaimsValidators);
            return this;
        }

        /**
         * Replaces any existing claim validators with the ones supplied.
         *
         * @param jwtClaimsValidators The claims validators to use
         * @return The builder
         */
        public Builder withClaimValidators(Collection<? extends JwtClaimsValidator> jwtClaimsValidators) {
            claimsValidators = new ArrayList<>(jwtClaimsValidators);
            return this;
        }

        /**
         * Builds the validator.
         *
         * @return The validator
         */
        public JwtValidator build() {
            return new JwtValidator(signatures, encryptions, claimsValidators);
        }
    }
}
