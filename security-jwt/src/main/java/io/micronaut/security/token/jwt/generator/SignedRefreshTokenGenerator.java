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
package io.micronaut.security.token.jwt.generator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.generator.RefreshTokenGenerator;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.text.ParseException;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * The default implementation of {@link RefreshTokenGenerator} and {@link RefreshTokenValidator}.
 * Create and verify a JWS encoded object whose payload is a UUID with a hash-based message authentication code (HMAC).
 * @see <a href="https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-hmac">JSON Web Signature (JWS) with HMAC protection</a>
 *
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Singleton
@Requires(beans = RefreshTokenConfiguration.class)
public class SignedRefreshTokenGenerator implements RefreshTokenGenerator, RefreshTokenValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SignedRefreshTokenGenerator.class);
    private final JWSAlgorithm algorithm;
    private final JWSVerifier verifier;
    private final JWSSigner signer;

    /**
     *
     * @param config Signed Refresh Token generator
     */
    public SignedRefreshTokenGenerator(RefreshTokenConfiguration config) {
        byte[] secret = config.isBase64() ? Base64.getDecoder().decode(config.getSecret()) : config.getSecret().getBytes(UTF_8);
        this.algorithm = config.getJwsAlgorithm();
        try {
            this.signer = new MACSigner(secret);
        } catch (JOSEException e) {
            throw new ConfigurationException("unable to create a signer", e);
        }
        try {
            this.verifier = new MACVerifier(secret);
        } catch (JOSEException e) {
            throw new ConfigurationException("unable to create a verifier", e);
        }
    }

    @NonNull
    @Override
    public String createKey(@NonNull UserDetails userDetails) {
        return UUID.randomUUID().toString();
    }

    @NonNull
    @Override
    public Optional<String> generate(@NonNull UserDetails userDetails, @NonNull String token) {
        try {
            JWSObject jwsObject = new JWSObject(new JWSHeader(algorithm), new Payload(token));
            jwsObject.sign(signer);
            return Optional.of(jwsObject.serialize());
        } catch (JOSEException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("JOSEException signing a JWS Object");
            }
        }
        return Optional.empty();
    }

    @NonNull
    @Override
    public Optional<String> validate(@NonNull String refreshToken) {
        JWSObject jwsObject = null;
        try {
            jwsObject = JWSObject.parse(refreshToken);
            if (jwsObject.verify(verifier)) {
                return Optional.of(jwsObject.getPayload().toString());
            }
        } catch (ParseException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Parse exception parsing refresh token {} into JWS Object", refreshToken);
            }
            return Optional.empty();
        } catch (JOSEException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("JOSEException parsing refresh token {} into JWS Object", refreshToken);
            }
        }
        return Optional.empty();
    }
}
