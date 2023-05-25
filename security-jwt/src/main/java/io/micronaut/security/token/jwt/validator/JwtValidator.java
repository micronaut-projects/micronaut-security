/*
 * Copyright 2017-2023 original authors
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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.encryption.EncryptionConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaimsSetAdapter;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksCache;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A builder style class for validating JWT tokens against any number of provided
 * encryption or signature configurations and any claim validators.
 *
 * @author James Kleeh
 * @since 1.4.0
 * @param <T> Request
 */
public final class JwtValidator<T> {

    private static final Logger LOG = LoggerFactory.getLogger(JwtValidator.class);
    private static final String DOT = ".";

    private final List<SignatureConfiguration> signatures;
    private final List<EncryptionConfiguration> encryptions;
    private final List<JwtClaimsValidator> claimsValidators;

    private JwtValidator(List<SignatureConfiguration> signatures,
                         List<EncryptionConfiguration> encryptions,
                         List<JwtClaimsValidator> claimsValidators) {
        this.signatures = signatures;
        this.encryptions = encryptions;
        this.claimsValidators = claimsValidators;
    }

    /**
     * Validates the supplied token with any configurations and claim validators present.
     *
     * @param token The JWT string
     * @param request HTTP Request
     * @return An optional JWT token if validation succeeds
     */
    public Optional<JWT> validate(String token, @Nullable T request) {
            try {
                if (hasAtLeastTwoDots(token)) {
                    JWT jwt = JWTParser.parse(token);
                    return validate(jwt, request);
                } else {
                    if (LOG.isTraceEnabled()) {
                        LOG.trace("token {} does not contain two dots", token);
                    }
                }
            } catch (final ParseException e) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Failed to parse JWT: {}", e.getMessage());
                }
            }
            return Optional.empty();
    }

    /**
     *
     * @param token The JWT string
     * @return {@literal true} if the string has at least two dots. We must have 2 (JWS) or 4 dots (JWE).
     */
    private boolean hasAtLeastTwoDots(String token) {
        return (token.contains(DOT)) &&
                (token.indexOf(DOT, token.indexOf(DOT) + 1) != -1);
    }

    /**
     * Validates the supplied token with any configurations and claim validators present.
     *
     * @param token The JWT token
     * @param request The HTTP Request which contained the JWT token
     * @return An optional JWT token if validation succeeds
     */
    public Optional<JWT> validate(@NonNull JWT token, @Nullable T request) {
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
                    Claims claims = new JwtClaimsSetAdapter(jwt.getJWTClaimsSet());
                    return claimsValidators.stream().allMatch(validator -> validator.validate(claims, request));
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
                LOG.trace("Using encryption configuration: {}", config);
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
                    LOG.debug("Decryption fails with encryption configuration: {}, passing to the next one", config);
                }
                return Optional.empty();
            }
        }

        if (LOG.isDebugEnabled() && encryptions.isEmpty()) {
            LOG.debug("JWT is encrypted and no encryption configurations -> not verified");
        }

        return Optional.empty();
    }

    private Optional<JWT> validate(SignedJWT jwt) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Validating signed JWT");
        }

        final JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        List<SignatureConfiguration> sortedConfigs = new ArrayList<>(signatures);
        sortedConfigs.sort(comparator(algorithm, jwt.getHeader().getKeyID()));

        Optional<JWT> optionalJWT = validate(jwt, sortedConfigs);
        if (optionalJWT.isPresent()) {
            return optionalJWT;
        }

        // If any of the signature configurations is a JwksCache, evict the cache and attempt to verify again
        for (SignatureConfiguration c : sortedConfigs) {
            if (c instanceof JwksCache && ((JwksCache) c).isExpired()) {
                ((JwksCache) c).clear();
                optionalJWT = validate(jwt, c);
                if (optionalJWT.isPresent()) {
                    return optionalJWT;
                }
            }
        }

        if (LOG.isDebugEnabled() && signatures.isEmpty()) {
            LOG.debug("JWT is signed and no signature configurations -> not verified");
        }
        return Optional.empty();
    }

    private Optional<JWT> validate(SignedJWT jwt, SignatureConfiguration signatureConfiguration) {
        try {
            boolean verified = signatureConfiguration.verify(jwt);
            if (!verified) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JWT Signature verification failed: {}", jwt.getParsedString());
                }
            } else {
                return Optional.of(jwt);
            }
        } catch (final JOSEException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verification failed with signature configuration: {}, passing to the next one", signatureConfiguration);
            }
        }
        return Optional.empty();
    }

    private Optional<JWT> validate(SignedJWT jwt, List<SignatureConfiguration> signatureConfigurations) {
        for (SignatureConfiguration config: signatureConfigurations) {
            Optional<JWT> optionalJWT = validate(jwt, config);
            if (optionalJWT.isPresent()) {
                return optionalJWT;
            }
        }
        return Optional.empty();
    }

    private static int compareKeyIds(SignatureConfiguration sig,
                                     SignatureConfiguration otherSig,
                                     @Nullable String keyId) {
        if (keyId == null) {
            return 0;
        }
        Optional<Boolean> matchesKeyId = signatureConfigurationMatchesKeyId(sig, keyId);
        Optional<Boolean> otherMatchesKeyId = signatureConfigurationMatchesKeyId(otherSig, keyId);
        if (matchesKeyId.isPresent() && otherMatchesKeyId.isPresent()) {
            return otherMatchesKeyId.get().compareTo(matchesKeyId.get());
        } else if (matchesKeyId.isPresent()) {
            return Boolean.TRUE.equals(matchesKeyId.get()) ? 1 : -1;
        } else if (otherMatchesKeyId.isPresent()) {
            return Boolean.TRUE.equals(otherMatchesKeyId.get()) ? 1 : -1;
        }
        return 0;
    }

    private static Comparator<SignatureConfiguration> comparator(JWSAlgorithm algorithm, @Nullable String kid) {
        return (sig, otherSig) -> {
            int compareKids = compareKeyIds(sig, otherSig, kid);
            if (compareKids != 0) {
                return compareKids;
            }
            boolean supports = signatureConfigurationSupportsAlgorithm(sig, algorithm);
            boolean otherSupports = signatureConfigurationSupportsAlgorithm(otherSig, algorithm);
            if (supports == otherSupports) {
                return 0;
            } else if (supports) {
                return -1;
            } else {
                return 1;
            }
        };
    }

    private static Optional<Boolean> signatureConfigurationMatchesKeyId(@NonNull SignatureConfiguration sig,
                                                                        @NonNull String keyId) {
        if (sig instanceof JwksCache) {
            final Optional<List<String>> keyIds = ((JwksCache) sig).getKeyIds();
            return keyIds.map(ids -> ids.contains(keyId));
        } else {
            return Optional.empty();
        }
    }

    private static boolean signatureConfigurationSupportsAlgorithm(@NonNull SignatureConfiguration sig, @NonNull JWSAlgorithm algorithm) {
        // {@link JwksSignature#supports} does an HTTP request if the Json Web Key Set is not present.
        // Thus, don't call it unless the keys have been already been fetched.
        if (!(sig instanceof JwksCache) || ((JwksCache) sig).isPresent()) {
            return sig.supports(algorithm);
        }
        return false;
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
     * @param <T> Request
     */
    public static final class Builder<T> {

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
        public JwtValidator<T> build() {
            return new JwtValidator(signatures, encryptions, claimsValidators);
        }
    }
}
