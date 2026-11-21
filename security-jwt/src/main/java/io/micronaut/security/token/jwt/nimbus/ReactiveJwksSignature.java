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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.security.token.IssuerUtils;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksClientReactorContext;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureUtils;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.text.ParseException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Signature configuration which enables verification of remote JSON Web Key Set.
 * A bean of this class is created for each {@link io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration}.
 * <p>
 * If the configuration is bound to an issuer ({@link JwksSignatureConfiguration#getIssuer()}), only tokens whose {@code iss}
 * claim matches that issuer (see {@link IssuerUtils#equivalent(String, String)}) are verified with the key set. Tokens issued
 * by another issuer, or without an {@code iss} claim, are not verified, even if their signature validates against one of the keys.
 * The issuer is a binding on the key set, which keys are trusted to sign tokens of which issuer, and is checked before the key
 * set is consulted. It does not replace the validation of the {@code iss} claim by the claims validators.
 * <p>
 * If the configuration specifies a {@link JwksSignatureConfiguration#getKeyType() key type}, only keys of that type ({@code kty})
 * are used to verify a token. A token signed with a key of another type is not verified, even if that key is part of the key set.
 * <p>
 * If the JWT carries a {@code kid} header which is not present in the cached JWKS, and the Reactor context
 * {@link JwksClientReactorContext} allows it, the JWKS cache is cleared and the JWKS is fetched again at most once
 * per {@link JwksSignatureConfiguration#getRefreshInterval()} so that key rotations at the authorization server are
 * picked up without waiting for the cache to expire.
 *
 * @author Sergio del Amo
 * @since 4.8.0
*/
@EachBean(JwksSignatureConfiguration.class)
public class ReactiveJwksSignature implements ReactiveSignatureConfiguration<SignedJWT> {
    private static final Logger LOG = LoggerFactory.getLogger(ReactiveJwksSignature.class);
    private final JwkValidator jwkValidator;
    private final JwksSignatureConfiguration jwksSignatureConfiguration;
    private final JwkSetFetcher<JWKSet> jwkSetFetcher;
    private final long refreshIntervalNanos;
    private final AtomicLong lastRefreshNanos;

    /**
     *
     * @param jwksSignatureConfiguration JSON Web Key Set configuration.
     * @param jwkValidator JWK Validator to be used.
     * @param jwkSetFetcher Json Web Key Set fetcher
     */
    public ReactiveJwksSignature(JwksSignatureConfiguration jwksSignatureConfiguration,
                                 JwkValidator jwkValidator,
                                 JwkSetFetcher<JWKSet> jwkSetFetcher) {
        this.jwksSignatureConfiguration = jwksSignatureConfiguration;
        this.jwkValidator = jwkValidator;
        this.jwkSetFetcher = jwkSetFetcher;
        this.refreshIntervalNanos = jwksSignatureConfiguration.getRefreshInterval().toNanos();
        // allow the first refresh straight away
        this.lastRefreshNanos = new AtomicLong(System.nanoTime() - refreshIntervalNanos);
    }

    /**
     * Verify a signed JWT. Emits {@code false} without consulting the key set if the configuration is bound to an issuer
     * and the {@code iss} claim of the JWT does not match it. Only keys whose type matches
     * {@link JwksSignatureConfiguration#getKeyType()} are considered, if a key type is configured.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     */
    @Override
    @SingleResult
    public Publisher<Boolean> verify(SignedJWT jwt) {
        if (!issuerMatches(jwt)) {
            return Mono.just(false);
        }
        String providerName = jwksSignatureConfiguration.getName();
        String url = jwksSignatureConfiguration.getUrl();
        return Mono.deferContextual(ctx -> Mono.from(jwkSetFetcher.fetch(providerName, url))
                .flatMap(jwkSet -> {
                    if (shouldRefresh(ctx, jwt, jwkSet)) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("JWT key ID {} not found in cached JWKS for {}. Clearing cache and fetching JWKS again", jwt.getHeader().getKeyID(), url);
                        }
                        jwkSetFetcher.clearCache(providerName, url);
                        return Mono.from(jwkSetFetcher.fetch(providerName, url))
                                .map(refreshedJwkSet -> verify(jwt, refreshedJwkSet));
                    }
                    return Mono.just(verify(jwt, jwkSet));
                }));
    }

    /**
     * @param ctx Reactor context
     * @param jwt the signed JWT
     * @param jwkSet the cached JSON Web Key Set
     * @return Whether the JWKS cache should be cleared and the JWKS fetched again before verifying the JWT.
     */
    private boolean shouldRefresh(ContextView ctx, SignedJWT jwt, JWKSet jwkSet) {
        String keyId = jwt.getHeader().getKeyID();
        if (keyId == null) {
            return false;
        }
        if (!ctx.hasKey(JwksClientReactorContext.class) || !ctx.get(JwksClientReactorContext.class).isRefreshOnUnknownKeyId()) {
            return false;
        }
        if (JwksSignatureUtils.containsKeyId(jwkSet, keyId)) {
            return false;
        }
        return tryAcquireRefresh();
    }

    /**
     * Rate limits refreshes so that concurrent tokens with an unknown key ID do not stampede the authorization server.
     * @return {@code true} if the caller is allowed to refresh the JWKS. Only one caller per {@link JwksSignatureConfiguration#getRefreshInterval()} is allowed.
     */
    private boolean tryAcquireRefresh() {
        long now = System.nanoTime();
        long last = lastRefreshNanos.get();
        if (now - last < refreshIntervalNanos) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWKS for {} was refreshed less than {} ago. Not refreshing again", jwksSignatureConfiguration.getUrl(), jwksSignatureConfiguration.getRefreshInterval());
            }
            return false;
        }
        return lastRefreshNanos.compareAndSet(last, now);
    }

    private boolean verify(SignedJWT jwt, JWKSet jwkSet) {
        try {
            boolean result = JwksSignatureUtils.verify(jwt, jwkSet, jwkValidator, jwksSignatureConfiguration.getKeyType());
            if (LOG.isDebugEnabled()) {
                if (result) {
                    LOG.debug("Signature verified for {}", JwtLogUtils.describe(jwt));
                } else {
                    LOG.debug("Signature not verified for {}", JwtLogUtils.describe(jwt));
                    if (!JwksSignatureUtils.supports(jwt.getHeader().getAlgorithm(), jwkSet)) {
                        LOG.debug("JWT Signature algorithm {} not supported by JWK Set. {} ", jwt.getHeader().getAlgorithm(), JwksSignatureUtils.supportedAlgorithmsMessage(jwkSet));
                    }
                }
            }
            return result;
        } catch (JOSEException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Error verifying JWT signature", e);
            }
            return false;
        }
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
                LOG.debug("JWT not verified with JWKS [{}]: failed to parse the claims set", jwksSignatureConfiguration.getName(), e);
            }
            return false;
        }
        if (iss == null || iss.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT not verified with JWKS [{}]: the JWT has no (or an empty) iss claim and the JWKS is bound to issuer [{}]", jwksSignatureConfiguration.getName(), issuer);
            }
            return false;
        }
        if (!IssuerUtils.equivalent(issuer, iss)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT not verified with JWKS [{}]: iss claim [{}] does not match the issuer [{}] the JWKS is bound to", jwksSignatureConfiguration.getName(), iss, issuer);
            }
            return false;
        }
        return true;
    }
}
