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

import java.util.concurrent.atomic.AtomicLong;

/**
 * Signature configuration which enables verification of remote JSON Web Key Set.
 * A bean of this class is created for each {@link io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration}.
 *
 * <p>If the JWT carries a {@code kid} header which is not present in the cached JWKS, and the Reactor context
 * {@link JwksClientReactorContext} allows it, the JWKS cache is cleared and the JWKS is fetched again at most once
 * per {@link JwksSignatureConfiguration#getRefreshInterval()} so that key rotations at the authorization server are
 * picked up without waiting for the cache to expire.</p>
 *
 * <p>If {@link JwksSignatureConfiguration#getKeyType()} is set, only keys of that key type are used to verify the JWT.</p>
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
     * Verify a signed JWT.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     */
    @Override
    @SingleResult
    public Publisher<Boolean> verify(SignedJWT jwt) {
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
            boolean result = JwksSignatureUtils.verify(jwt, jwkSet, jwksSignatureConfiguration.getKeyType(), jwkValidator);
            if (LOG.isDebugEnabled()) {
                if (result) {
                    LOG.debug("JWT Signature verified: {}", jwt.getParsedString());
                } else {
                    LOG.debug("JWT Signature not verified: {}", jwt.getParsedString());
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
}
