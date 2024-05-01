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
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureUtils;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * Signature configuration which enables verification of remote JSON Web Key Set.
 * A bean of this class is created for each {@link io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration}.
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
     * Verify a signed JWT.
     *
     * @param jwt the signed JWT
     * @return whether the signed JWT is verified
     */
    @Override
    @SingleResult
    public Publisher<Boolean> verify(SignedJWT jwt) {
        return Mono.from(jwkSetFetcher.fetch(jwksSignatureConfiguration.getName(), jwksSignatureConfiguration.getUrl()))
                .map(jwkSet -> {
                    try {
                        boolean result = JwksSignatureUtils.verify(jwt, jwkSet, jwkValidator);
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
                });
    }
}
