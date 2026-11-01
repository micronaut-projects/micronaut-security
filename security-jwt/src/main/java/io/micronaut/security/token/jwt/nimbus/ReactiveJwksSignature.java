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
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureUtils;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;

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
 * The issuer and the url of the key set are resolved inside the reactive chain, so that a configuration which cannot resolve them
 * yet (for example, the {@code jwks_uri} of an OpenID provider whose discovery document is not available) fails the verification
 * instead of failing the request.
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
    }

    /**
     * Verify a signed JWT. Emits {@code false} without consulting the key set if the configuration is bound to an issuer
     * and the {@code iss} claim of the JWT does not match it. Only keys whose type matches
     * {@link JwksSignatureConfiguration#getKeyType()} are considered, if a key type is configured.
     * Emits {@code false} if the issuer or the url of the key set cannot be resolved, or if the key set cannot be verified against.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     */
    @Override
    @SingleResult
    public Publisher<Boolean> verify(SignedJWT jwt) {
        return Mono.defer(() -> {
                    if (!issuerMatches(jwt)) {
                        return Mono.just(false);
                    }
                    return Mono.fromCallable(jwksSignatureConfiguration::getUrl)
                            .flatMap(url -> Mono.from(jwkSetFetcher.fetch(jwksSignatureConfiguration.getName(), url)))
                            .map(jwkSet -> verify(jwt, jwkSet));
                })
                .onErrorResume(e -> {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("JWT signature not verified with JWKS [{}]: {}", jwksSignatureConfiguration.getName(), e.getMessage());
                        LOG.debug("Error verifying JWT signature with JWKS [{}]", jwksSignatureConfiguration.getName(), e);
                    }
                    return Mono.just(false);
                });
    }

    private boolean verify(SignedJWT jwt, JWKSet jwkSet) {
        try {
            boolean result = JwksSignatureUtils.verify(jwt, jwkSet, jwkValidator, jwksSignatureConfiguration.getKeyType());
            if (LOG.isDebugEnabled()) {
                if (result) {
                    LOG.debug("JWT Signature verified");
                } else {
                    LOG.debug("JWT Signature not verified");
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
