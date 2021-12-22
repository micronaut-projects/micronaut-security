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
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.core.annotation.Nullable;
import jakarta.inject.Inject;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Signature configuration which enables verification of remote JSON Web Key Set.
 *
 * A bean of this class is created for each {@link io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@EachBean(JwksSignatureConfiguration.class)
public class JwksSignature implements JwksCache, SignatureConfiguration {

    @Deprecated
    public static final int DEFAULT_REFRESH_JWKS_ATTEMPTS = 1;

    private static final Logger LOG = LoggerFactory.getLogger(JwksSignature.class);
    private final JwkValidator jwkValidator;
    private final JwksSignatureConfiguration jwksSignatureConfiguration;
    private volatile Instant jwkSetCachedAt;
    private volatile JWKSet jwkSet;
    private final JwkSetFetcher<JWKSet> jwkSetFetcher;

    /**
     *
     * @param jwksSignatureConfiguration JSON Web Key Set configuration.
     * @param jwkValidator JWK Validator to be used.
     * @param jwkSetFetcher Json Web Key Set fetcher
     */
    @Inject
    public JwksSignature(JwksSignatureConfiguration jwksSignatureConfiguration,
                         JwkValidator jwkValidator,
                         JwkSetFetcher<JWKSet> jwkSetFetcher) {
        this.jwksSignatureConfiguration = jwksSignatureConfiguration;
        this.jwkValidator = jwkValidator;
        this.jwkSetFetcher = jwkSetFetcher;
    }

    /**
     *
     * @param jwksSignatureConfiguration JSON Web Key Set configuration.
     * @param jwkValidator JWK Validator to be used.
     * @deprecated Use {@link #JwksSignature(JwksSignatureConfiguration, JwkValidator, JwkSetFetcher)} instead.
     */
    @Deprecated
    public JwksSignature(JwksSignatureConfiguration jwksSignatureConfiguration,
                         JwkValidator jwkValidator) {
        this(jwksSignatureConfiguration, jwkValidator, new DefaultJwkSetFetcher());
    }

    /**
     * @param url The JWK url
     * @param keyType The JWK key type
     * @param jwkValidator JWK Validator to be used.
     * @deprecated Use {@link #JwksSignature(JwksSignatureConfiguration, JwkValidator, JwkSetFetcher)} instead.
     */
    @Deprecated
    public JwksSignature(String url,
                         @Nullable KeyType keyType,
                         JwkValidator jwkValidator) {
        this(new JwksSignatureConfiguration() {
            @Override
            @NonNull
            public String getUrl() {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JWT validation URL: {}", url);
                }
                return url;
            }

            @Override
            public KeyType getKeyType() {
                return keyType;
            }

            @Override
            @NonNull
            public Integer getCacheExpiration() {
                return JwksSignatureConfigurationProperties.DEFAULT_CACHE_EXPIRATION;
            }
        }, jwkValidator, new DefaultJwkSetFetcher());
    }

    private Optional<JWKSet> getJWKSet() {
        JWKSet jwkSet = this.jwkSet;
        if (jwkSet == null) {
            synchronized (this) { // double check
                jwkSet = this.jwkSet;
                if (jwkSet == null) {
                    jwkSet = loadJwkSet(this.jwksSignatureConfiguration.getUrl());
                    this.jwkSet = jwkSet;
                    this.jwkSetCachedAt = Instant.now().plus(this.jwksSignatureConfiguration.getCacheExpiration(), ChronoUnit.SECONDS);
                }
            }
        }
        return Optional.ofNullable(jwkSet);
    }

    private List<JWK> getJsonWebKeys() {
        return getJWKSet().map(JWKSet::getKeys).orElse(Collections.emptyList());
    }

    @Override
    public boolean isExpired() {
        Instant cachedAt = jwkSetCachedAt;
        return cachedAt != null && Instant.now().isAfter(cachedAt);
    }

    @Override
    public void clear() {
        jwkSetFetcher.clearCache(jwksSignatureConfiguration.getUrl());
        jwkSet = null;
        jwkSetCachedAt = null;
    }

    @Override
    public boolean isPresent() {
        return jwkSet != null;
    }

    @Override
    @NonNull
    public Optional<List<String>> getKeyIds() {
        JWKSet jwkSet = this.jwkSet;
        if (jwkSet != null) {
            List<String> keyIds = new ArrayList<>(jwkSet.getKeys().size());
            for (JWK key : jwkSet.getKeys()) {
                String keyId = key.getKeyID();
                if (keyId != null) {
                    keyIds.add(keyId);
                }
            }
            if (keyIds.isEmpty()) {
                return Optional.empty();
            } else {
                return Optional.of(keyIds);
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @return A message indicating the supported algorithms.
     */
    @Override
    public String supportedAlgorithmsMessage() {
        String message = getJsonWebKeys().stream()
                .map(JWK::getAlgorithm)
                .map(Algorithm::getName)
                .reduce((a, b) -> a + ", " + b)
                .map(s -> "Only the " + s)
                .orElse("No");
        return message + " algorithms are supported";
    }

    /**
     * Whether this signature configuration supports this algorithm.
     *
     * @param algorithm the signature algorithm
     * @return whether this signature configuration supports this algorithm
     */
    @Override
    public boolean supports(JWSAlgorithm algorithm) {
        return getJsonWebKeys()
                .stream()
                .map(JWK::getAlgorithm)
                .anyMatch(algorithm::equals);
    }

    /**
     * Verify a signed JWT.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     * @throws JOSEException exception when verifying the JWT
     */
    @Override
    public boolean verify(SignedJWT jwt) throws JOSEException {
        List<JWK> matches = matches(jwt, getJWKSet().orElse(null));
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found {} matching JWKs", matches.size());
        }
        if (matches == null || matches.isEmpty()) {
            return false;
        }
        return verify(matches, jwt);
    }

    /**
     * Instantiates a JWKSet for a given url.
     * @param url JSON Web Key Set Url.
     * @return a JWKSet or null if there was an error.
     */
    @Nullable
    protected JWKSet loadJwkSet(String url) {
        return jwkSetFetcher.fetch(url)
                .orElse(null);
    }

    /**
     * Calculates a list of JWK matches for a JWT.
     *
     *
     * @param jwt A Signed JWT
     * @param jwkSet A JSON Web Key Set
     * @param refreshKeysAttempts Number of times to attempt refreshing the JWK Set
     * @deprecated Use {@link JwksSignature#matches(SignedJWT, JWKSet)} instead
     * @return a List of JSON Web Keys
     */
    @Deprecated
    protected List<JWK> matches(SignedJWT jwt, @Nullable JWKSet jwkSet, int refreshKeysAttempts) {
        return matches(jwt, jwkSet);
    }

    /**
     * Calculates a list of JWK matches for a JWT.
     *
     * @param jwt A Signed JWT
     * @param jwkSet A JSON Web Key Set
     * @return a List of JSON Web Keys
     */
    protected List<JWK> matches(SignedJWT jwt, @Nullable JWKSet jwkSet) {
        List<JWK> matches = Collections.emptyList();
        if (jwkSet != null) {
            JWKMatcher.Builder builder = new JWKMatcher.Builder();
            if (jwksSignatureConfiguration.getKeyType() != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key Type: {}", jwksSignatureConfiguration.getKeyType());
                }
                builder = builder.keyType(jwksSignatureConfiguration.getKeyType());
            }
            String keyId = jwt.getHeader().getKeyID();
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT Key ID: {}", keyId);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWK Set Key IDs: {}", String.join(",", getKeyIds().orElse(Collections.emptyList())));
            }
            if (keyId != null) {
                builder = builder.keyID(keyId);
            }

            matches = new JWKSelector(builder.build()).select(jwkSet);
        }
        return matches;
    }

    /**
     * returns true if any JWK match is able to verify the JWT signature.
     *
     * @param matches A List of JSON Web key matches.
     * @param jwt A JWT to be verified.
     * @return true if the JWT signature could be verified.
     */
    protected boolean verify(List<JWK> matches, SignedJWT jwt) {
        return matches.stream().anyMatch(jwk -> jwkValidator.validate(jwt, jwk));
    }

    /**
     * Returns the number of attempts to refresh the cached JWKS.
     * @return Number of attempts to refresh the cached JWKS.
     */
    @Deprecated
    public int getRefreshJwksAttempts() {
        return DEFAULT_REFRESH_JWKS_ATTEMPTS;
    }

    /**
     *
     * @return A JSON Web Key Validator.
     */
    @Deprecated
    public JwkValidator getJwkValidator() {
        return jwkValidator;
    }

    /**
     *
     * @return a JSON Web Key Set.
     */
    @Deprecated
    public JWKSet getJwkSet() {
        return jwkSet;
    }

    /**
     *
     * @return the Key Type.
     */
    @Deprecated
    public KeyType getKeyType() {
        return jwksSignatureConfiguration.getKeyType();
    }

    /**
     *
     * @return The JSON Web Key Set (JWKS) URL.
     */
    @Deprecated
    public String getUrl() {
        return jwksSignatureConfiguration.getUrl();
    }
}
