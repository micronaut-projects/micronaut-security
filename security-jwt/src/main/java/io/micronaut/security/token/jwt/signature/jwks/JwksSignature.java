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
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
    public JwksSignature(JwksSignatureConfiguration jwksSignatureConfiguration,
                         JwkValidator jwkValidator,
                         JwkSetFetcher<JWKSet> jwkSetFetcher) {
        this.jwksSignatureConfiguration = jwksSignatureConfiguration;
        this.jwkValidator = jwkValidator;
        this.jwkSetFetcher = jwkSetFetcher;
    }

    private Optional<JWKSet> computeJWKSet() {
        JWKSet jwkSetVariable = this.jwkSet;
        if (jwkSetVariable == null) {
            synchronized (this) { // double check
                jwkSetVariable = this.jwkSet;
                if (jwkSetVariable == null) {
                    jwkSetVariable = loadJwkSet(this.jwksSignatureConfiguration.getName(), this.jwksSignatureConfiguration.getUrl());
                    this.jwkSet = jwkSetVariable;
                    this.jwkSetCachedAt = Instant.now().plus(this.jwksSignatureConfiguration.getCacheExpiration(), ChronoUnit.SECONDS);
                }
            }
        }
        return Optional.ofNullable(jwkSetVariable);
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
     * Verify a signed JWT.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     * @throws JOSEException exception when verifying the JWT
     */
    @Override
    public boolean verify(SignedJWT jwt) throws JOSEException {
        return JwksSignatureUtils.verify(jwt, computeJWKSet().orElse(null), jwkValidator);
    }

    /**
     * Instantiates a JWKSet for a given url.
     * @param url JSON Web Key Set Url.
     * @return a JWKSet or null if there was an error.
     * @deprecated Use {@link #loadJwkSet(String, String)} instead.
     */
    @Nullable
    @Blocking
    @Deprecated(forRemoval = true, since = "4.5.0")
    protected JWKSet loadJwkSet(String url) {
        return Mono.from(jwkSetFetcher.fetch(null, url))
                .blockOptional()
                .orElse(null);
    }

    /**
     * Instantiates a JWKSet for a given url.
     * @param providerName The name of the JWKS configuration.
     * @param url JSON Web Key Set Url.
     * @return a JWKSet or null if there was an error.
     */
    @Nullable
    @Blocking
    protected JWKSet loadJwkSet(@Nullable String providerName, String url) {
        return Mono.from(jwkSetFetcher.fetch(providerName, url)).blockOptional().orElse(null);
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
}
