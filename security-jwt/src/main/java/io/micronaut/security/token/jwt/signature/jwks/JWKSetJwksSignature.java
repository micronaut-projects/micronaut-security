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
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.token.jwt.signature.SignatureConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link SignatureConfiguration} backed by a {@link JWKSet}.
 */
@Internal
public class JWKSetJwksSignature implements SignatureConfiguration<SignedJWT, JWSAlgorithm> {
    private static final Logger LOG = LoggerFactory.getLogger(JWKSetJwksSignature.class);

    private final JWKSet jwkSet;
    private final JwkValidator jwkValidator;

    public JWKSetJwksSignature(JwkValidator jwkValidator, JWKSet jwkSet) {
        this.jwkValidator = jwkValidator;
        this.jwkSet = jwkSet;
    }

    /**
     *
     * @return A message indicating the supported algorithms.
     */
    public String supportedAlgorithmsMessage() {
        return JwksSignatureUtils.supportedAlgorithmsMessage(jwkSet);
    }

    /**
     * Whether this signature configuration supports this algorithm.
     *
     * @param algorithm the signature algorithm
     * @return whether this signature configuration supports this algorithm
     */
    @Override
    public boolean supports(JWSAlgorithm algorithm) {
        return JwksSignatureUtils.supports(algorithm, jwkSet);
    }

    @Override
    public boolean verify(SignedJWT jwt) throws JOSEException {
        return JwksSignatureUtils.verify(jwt, jwkSet, jwkValidator);
    }

}
