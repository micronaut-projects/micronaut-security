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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Signature configuration which enables verification of remote JSON Web Key Set.
 * <p>
 * If the configuration is bound to an issuer ({@link JwksSignatureConfiguration#getIssuer()}), only tokens whose {@code iss}
 * claim matches that issuer (see {@link IssuerUtils#equivalent(String, String)}) are verified with the key set. Tokens issued
 * by another issuer, or without an {@code iss} claim, are not verified, even if their signature validates against one of the keys.
 * The issuer is a binding on the key set, which keys are trusted to sign tokens of which issuer, and is checked before the key
 * set is consulted. It does not replace the validation of the {@code iss} claim by the claims validators.
 * <p>
 * If the configuration specifies a {@link JwksSignatureConfiguration#getKeyType() key type}, only keys of that type ({@code kty})
 * are used to verify a token. A token signed with a key of another type is not verified, even if that key is part of the key set.
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

    private Optional<JWKSet> computeJWKSet() {
        JWKSet jwkSetVariable = this.jwkSet;
        if (jwkSetVariable == null) {
            synchronized (this) { // double check
                jwkSetVariable = this.jwkSet;
                if (jwkSetVariable == null) {
                    Optional<String> url = resolveUrl();
                    if (!url.isPresent()) {
                        return Optional.empty();
                    }
                    jwkSetVariable = loadJwkSet(url.get());
                    this.jwkSet = jwkSetVariable;
                    this.jwkSetCachedAt = Instant.now().plus(this.jwksSignatureConfiguration.getCacheExpiration(), ChronoUnit.SECONDS);
                }
            }
        }
        return Optional.ofNullable(jwkSetVariable);
    }

    /**
     * Resolves the url of the key set. A configuration which cannot resolve it yet (for example, the {@code jwks_uri} of an
     * OpenID provider whose discovery document is not available) must fail the verification instead of failing the request.
     *
     * @return The url, or empty if it cannot be resolved
     */
    @NonNull
    private Optional<String> resolveUrl() {
        try {
            return Optional.ofNullable(jwksSignatureConfiguration.getUrl());
        } catch (RuntimeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT signature not verified with JWKS: {}", e.getMessage());
                LOG.debug("Error resolving the JWKS url", e);
            }
            return Optional.empty();
        }
    }

    private List<JWK> getJsonWebKeys() {
        return computeJWKSet().map(JWKSet::getKeys).orElse(Collections.emptyList());
    }

    @Override
    public boolean isExpired() {
        Instant cachedAt = jwkSetCachedAt;
        return cachedAt != null && Instant.now().isAfter(cachedAt);
    }

    @Override
    public void clear() {
        resolveUrl().ifPresent(jwkSetFetcher::clearCache);
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
        return computeJWKSet()
            .map(JWKSet::getKeys)
            .map(jwkList -> jwkList.stream()
                    .map(JWK::getKeyID)
                    .collect(Collectors.toList())
            );
    }

    /**
     *
     * @return A message indicating the supported algorithms.
     */
    @Override
    public String supportedAlgorithmsMessage() {
        return JwksSignatureUtils.supportedAlgorithmsMessage(getJsonWebKeys());
    }

    /**
     * Whether this signature configuration supports this algorithm.
     *
     * @param algorithm the signature algorithm
     * @return whether this signature configuration supports this algorithm
     */
    @Override
    public boolean supports(JWSAlgorithm algorithm) {
        return JwksSignatureUtils.supports(algorithm, getJsonWebKeys());
    }

    /**
     * Verify a signed JWT. Returns {@code false} without consulting the key set if the configuration is bound to an issuer
     * and the {@code iss} claim of the JWT does not match it. Only keys whose type matches
     * {@link JwksSignatureConfiguration#getKeyType()} are considered, if a key type is configured.
     * Returns {@code false} if the url of the key set cannot be resolved or the key set cannot be loaded.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     * @throws JOSEException exception when verifying the JWT
     */
    @Override
    public boolean verify(SignedJWT jwt) throws JOSEException {
        if (!issuerMatches(jwt)) {
            return false;
        }
        return JwksSignatureUtils.verify(jwt, computeJWKSet().orElse(null), jwkValidator, jwksSignatureConfiguration.getKeyType());
    }

    /**
     * @return The issuer this JSON Web Key Set is bound to, or {@code null} if tokens are verified regardless of their {@code iss} claim.
     * @since 3.11.3
     */
    @Nullable
    public String getIssuer() {
        return jwksSignatureConfiguration.getIssuer();
    }

    /**
     * @param jwt the signed JWT
     * @return {@code true} if the configuration is not bound to an issuer or the {@code iss} claim of the JWT matches the bound issuer
     */
    private boolean issuerMatches(SignedJWT jwt) {
        String issuer = jwksSignatureConfiguration.getIssuer();
        if (issuer == null) {
            return true;
        }
        String iss;
        try {
            iss = jwt.getJWTClaimsSet().getIssuer();
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT not verified with JWKS [{}]: failed to parse the claims set", jwksDescription(), e);
            }
            return false;
        }
        if (iss == null || iss.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT not verified with JWKS [{}]: the JWT has no (or an empty) iss claim and the JWKS is bound to issuer [{}]", jwksDescription(), issuer);
            }
            return false;
        }
        if (!IssuerUtils.equivalent(issuer, iss)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT not verified with JWKS [{}]: iss claim [{}] does not match the issuer [{}] the JWKS is bound to", jwksDescription(), iss, issuer);
            }
            return false;
        }
        return true;
    }

    /**
     * @return The url of the key set for log messages, or a placeholder if it cannot be resolved
     */
    @NonNull
    private String jwksDescription() {
        try {
            return String.valueOf(jwksSignatureConfiguration.getUrl());
        } catch (RuntimeException e) {
            return "unresolved url";
        }
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
     * @deprecated Use {@link JwksSignatureUtils#matches(SignedJWT, JWKSet, KeyType)} instead.
     */
    @Deprecated
    protected List<JWK> matches(SignedJWT jwt, @Nullable JWKSet jwkSet) {
        return JwksSignatureUtils.matches(jwt, jwkSet, jwksSignatureConfiguration.getKeyType());
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
