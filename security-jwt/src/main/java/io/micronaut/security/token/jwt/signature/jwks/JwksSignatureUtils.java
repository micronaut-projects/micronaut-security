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
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
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
        return verify(jwt, jwkSet, null, jwkValidator);
    }

    /**
     * Verify a signed JWT only with keys of the given key type.
     *
     * @param jwt the signed JWT
     * @param jwkSet JSON Web Key Set
     * @param keyType Key Type. If {@code null}, keys of any key type are used.
     * @param jwkValidator JWK Validator
     * @return whether the signed JWT is verified
     * @throws JOSEException exception when verifying the JWT
     * @since 5.4.0
     */
    public static boolean verify(SignedJWT jwt, JWKSet jwkSet, @Nullable KeyType keyType, JwkValidator jwkValidator) throws JOSEException {
        List<JWK> matches = matches(jwt, jwkSet, keyType);
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
        return supports(algorithm, jwkSet.getKeys());
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
            .filter(Objects::nonNull)
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
        return keys.stream()
            .map(JWK::getAlgorithm)
            .filter(Objects::nonNull)
            .map(Algorithm::getName)
            .distinct()
            .reduce((a, b) -> a + ", " + b)
            .map(s -> "Algorithms supported: " + s)
            .orElse("No algorithms are supported");
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
     * @param jwkSet A JSON Web Key Set
     * @param keyId A Key ID
     * @return Whether the JSON Web Key Set contains a key with the given Key ID.
     * @since 5.4.0
     */
    public static boolean containsKeyId(@Nullable JWKSet jwkSet, @NonNull String keyId) {
        return jwkSet != null && jwkSet.getKeyByKeyId(keyId) != null;
    }

    /**
     * Calculates a list of JWK matches for a JWT.
     * A key matches if its Key ID equals the JWT {@code kid} header (when present), its key type equals {@code keyType}
     * (when given) and it is {@link #isEligibleForVerification(JWK, JWSAlgorithm) eligible} to verify the JWT algorithm.
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

            JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
            matches = new JWKSelector(builder.build()).select(jwkSet)
                .stream()
                .filter(jwk -> isEligibleForVerification(jwk, algorithm))
                .toList();
        }
        return matches;
    }

    /**
     * Whether a JSON Web Key may be used to verify a signature produced with the given algorithm.
     * A key is eligible only if its {@code use} is absent or {@code sig}, its {@code key_ops} is absent or contains
     * {@code verify}, and its {@code alg} is absent or equal to the JWS algorithm of the token.
     * Keys published for encryption, keys not intended for verification, and keys bound to a different algorithm
     * are never used to verify a signature, even if their Key ID matches.
     *
     * @param jwk A JSON Web Key
     * @param algorithm The JWS algorithm of the token header
     * @return whether the key may be used to verify a signature produced with the algorithm
     * @since 5.4.0
     */
    public static boolean isEligibleForVerification(@NonNull JWK jwk, @Nullable JWSAlgorithm algorithm) {
        KeyUse keyUse = jwk.getKeyUse();
        if (keyUse != null && !KeyUse.SIGNATURE.equals(keyUse)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWK with Key ID {} skipped: use {} is not sig", jwk.getKeyID(), keyUse);
            }
            return false;
        }
        Set<KeyOperation> keyOperations = jwk.getKeyOperations();
        if (keyOperations != null && !keyOperations.contains(KeyOperation.VERIFY)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWK with Key ID {} skipped: key_ops {} does not contain verify", jwk.getKeyID(), keyOperations);
            }
            return false;
        }
        Algorithm keyAlgorithm = jwk.getAlgorithm();
        if (keyAlgorithm != null && !keyAlgorithm.equals(algorithm)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("JWK with Key ID {} skipped: alg {} does not match token alg {}", jwk.getKeyID(), keyAlgorithm, algorithm);
            }
            return false;
        }
        return true;
    }
}
