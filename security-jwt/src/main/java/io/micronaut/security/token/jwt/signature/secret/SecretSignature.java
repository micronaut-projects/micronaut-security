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
package io.micronaut.security.token.jwt.signature.secret;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.impl.MACProvider;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.jwt.signature.AbstractSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.SignatureGeneratorConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@EachBean(SecretSignatureConfiguration.class)
public class SecretSignature extends AbstractSignatureConfiguration implements SignatureGeneratorConfiguration<SignedJWT, JWSAlgorithm> {
    private static final Logger LOG = LoggerFactory.getLogger(SecretSignature.class);

    private byte[] secret;

    /**
     *
     * @param config {@link SecretSignatureConfiguration} configuration
     */
    public SecretSignature(SecretSignatureConfiguration config) {
        Objects.requireNonNull(config.getSecret(), "The secret for the secret signature cannot be null");
        this.secret = config.isBase64() ? Base64.getDecoder().decode(config.getSecret()) : config.getSecret().getBytes(UTF_8);
        this.algorithm = config.getJwsAlgorithm();
    }

    /**
     *
     * @return message explaining the supported algorithms
     */
    public String supportedAlgorithmsMessage() {
        return "Only the HS256, HS384 and HS512 algorithms are supported for HMac signature";
    }

    public boolean supports(final JWSAlgorithm algorithm) {
        return algorithm != null && MACProvider.SUPPORTED_ALGORITHMS.contains(algorithm);
    }

    public SignedJWT sign(final Claims claims) throws JOSEException, ParseException {
        final JWSSigner signer = new MACSigner(this.secret);
        final SignedJWT signedJWT = new SignedJWT(new JWSHeader(algorithm), JWTClaimsSet.parse(claims.toMap()));
        signedJWT.sign(signer);
        return signedJWT;
    }

    @Override
    public boolean verify(final SignedJWT jwt) throws JOSEException {
        final JWSVerifier verifier = new MACVerifier(this.secret);
        boolean result = jwt.verify(verifier);
        if (LOG.isDebugEnabled()) {
            if (result) {
                LOG.debug("Secret Signature verification passed: {}", jwt.getParsedString());
            } else {
                LOG.debug("Secret Signature verification failed: {}", jwt.getParsedString());
                if (!supports(jwt.getHeader().getAlgorithm())) {
                    LOG.debug("JWT Signature algorithm {} not supported. {} ", jwt.getHeader().getAlgorithm(), supportedAlgorithmsMessage());
                }
            }
        }
        return result;
    }

    /**
     *
     * @return a string build the secret byte[] and UTF_8 charset
     */
    public String getSecret() {
        return new String(secret, UTF_8);
    }

    /**
     * Sets secret byte[] with a string with UTF_8 charset.
     * @param secret UTF_8 string
     */
    public void setSecret(final String secret) {
        this.secret = secret.getBytes(UTF_8);
    }
}
