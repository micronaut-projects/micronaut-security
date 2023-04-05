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

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class to verify signatures with a {@link JWKSet}.
 */
@Internal
public final class JwksSignatureUtils {

    private static final Logger LOG = LoggerFactory.getLogger(JwksSignatureUtils.class);

    private JwksSignatureUtils() {

    }

    /**
     * Verify a signed JWT.
     *
     * @param jwkSet JSON Web Key Set
     * @param jwt the signed JWT
     * @param jwkValidator JWK Validator
     * @return whether the signed JWT is verified
     * @throws JOSEException exception when verifying the JWT
     */
    public static boolean verify(SignedJWT jwt, JWKSet jwkSet, JwkValidator jwkValidator) throws JOSEException {
        List<JWK> matches = matches(jwt, jwkSet, null);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Found {} matching JWKs", matches.size());
        }
        return CollectionUtils.isNotEmpty(matches) && verify(jwkValidator, matches, jwt);
    }

    /**
     * Whether this signature configuration supports this algorithm.
     *
     * @param jwkSet JSON Web Key Set
     * @param algorithm the signature algorithm
     * @return whether this signature configuration supports this algorithm
     */
    public static boolean supports(JWSAlgorithm algorithm, JWKSet jwkSet) {
        return jwkSet.getKeys()
            .stream()
            .map(JWK::getAlgorithm)
            .anyMatch(algorithm::equals);
    }

    /**
     * Whether this signature configuration supports this algorithm.
     *
     * @param keys JSON Web Keys
     * @param algorithm the signature algorithm
     * @return whether this signature configuration supports this algorithm
     */
    public static boolean supports(JWSAlgorithm algorithm, List<JWK> keys) {
        return keys
            .stream()
            .map(JWK::getAlgorithm)
            .anyMatch(algorithm::equals);
    }

    /**
     * @param jwkSet JSON Web Key Set
     * @return A message indicating the supported algorithms.
     */
    public static String supportedAlgorithmsMessage(JWKSet jwkSet) {
        return supportedAlgorithmsMessage(jwkSet.getKeys());
    }

    /**
     * @param keys JSON Web Keys
     * @return A message indicating the supported algorithms.
     */
    public static String supportedAlgorithmsMessage(List<JWK> keys) {
        String message = keys.stream()
            .map(JWK::getAlgorithm)
            .map(Algorithm::getName)
            .reduce((a, b) -> a + ", " + b)
            .map(s -> "Only the " + s)
            .orElse("No");
        return message + " algorithms are supported";
    }

    /**
     * returns true if any JWK match is able to verify the JWT signature.
     *
     * @param jwkValidator JWK Validator
     * @param matches A List of JSON Web key matches.
     * @param jwt A JWT to be verified.
     * @return true if the JWT signature could be verified.
     */
    public static boolean verify(JwkValidator jwkValidator, List<JWK> matches, SignedJWT jwt) {
        return matches.stream().anyMatch(jwk -> jwkValidator.validate(jwt, jwk));
    }

    /**
     * Calculates a list of JWK matches for a JWT.
     *
     * @param jwt A Signed JWT
     * @param jwkSet A JSON Web Key Set
     * @param keyType Key Type
     * @return a List of JSON Web Keys
     */
    public static List<JWK> matches(SignedJWT jwt, @Nullable JWKSet jwkSet, @Nullable KeyType keyType) {
        List<JWK> matches = Collections.emptyList();
        if (jwkSet != null) {
            JWKMatcher.Builder builder = new JWKMatcher.Builder();
            if (keyType != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Key Type: {}", keyType);
                }
                builder = builder.keyType(keyType);
            }
            String keyId = jwt.getHeader().getKeyID();
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWT Key ID: {}", keyId);
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWK Set Key IDs: {}", jwkSet.getKeys().stream().map(JWK::getKeyID).collect(Collectors.joining(",")));
            }
            if (keyId != null) {
                builder = builder.keyID(keyId);
            }

            matches = new JWKSelector(builder.build()).select(jwkSet);
        }
        return matches;
    }
}
