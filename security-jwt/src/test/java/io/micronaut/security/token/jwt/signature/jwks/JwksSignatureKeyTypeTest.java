/*
 * Copyright 2017-2026 original authors
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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link JwksSignature} only verifies tokens with keys of the configured
 * {@link JwksSignatureConfiguration#getKeyType() key type}, when one is configured.
 */
class JwksSignatureKeyTypeTest {
    private static final RSAKey RSA_KEY = generateRsaKey();
    private static final ECKey EC_KEY = generateEcKey();
    private static final JWKSet JWK_SET = new JWKSet(Arrays.asList(RSA_KEY.toPublicJWK(), EC_KEY.toPublicJWK()));

    @Test
    void rsaKeyTypeVerifiesRsaSignedToken() {
        assertTrue(verify(signature(KeyType.RSA), rsaSignedJwt()));
    }

    @Test
    void rsaKeyTypeRejectsEcSignedTokenEvenIfTheEcKeyIsInTheSet() {
        assertFalse(verify(signature(KeyType.RSA), ecSignedJwt()));
    }

    @Test
    void ecKeyTypeVerifiesEcSignedToken() {
        assertTrue(verify(signature(KeyType.EC), ecSignedJwt()));
    }

    @Test
    void ecKeyTypeRejectsRsaSignedTokenEvenIfTheRsaKeyIsInTheSet() {
        assertFalse(verify(signature(KeyType.EC), rsaSignedJwt()));
    }

    @Test
    void withoutKeyTypeAnyKeyOfTheSetVerifies() {
        JwksSignature signature = signature(null);
        assertTrue(verify(signature, rsaSignedJwt()));
        assertTrue(verify(signature, ecSignedJwt()));
    }

    @Test
    void keyPublishedWithAnotherAlgorithmIsNotUsed() {
        RSAKey rs384 = new RSAKey.Builder(RSA_KEY.toPublicJWK()).algorithm(JWSAlgorithm.RS384).build();
        JWKSet set = new JWKSet(rs384);
        assertTrue(JwksSignatureUtils.matches(rsaSignedJwt(), set, KeyType.RSA).isEmpty());
    }

    @Test
    void keyPublishedWithTheTokenAlgorithmOrWithoutAlgorithmIsUsed() {
        RSAKey rs256 = new RSAKey.Builder(RSA_KEY.toPublicJWK()).algorithm(JWSAlgorithm.RS256).build();
        assertEquals(1, JwksSignatureUtils.matches(rsaSignedJwt(), new JWKSet(rs256), KeyType.RSA).size());
        assertEquals(1, JwksSignatureUtils.matches(rsaSignedJwt(), new JWKSet(RSA_KEY.toPublicJWK()), KeyType.RSA).size());
    }

    @Test
    void unknownKeyTypeFailsStartup() {
        RuntimeException e = assertThrows(RuntimeException.class, () -> {
            try (ApplicationContext context = ApplicationContext.run(configuration(
                "micronaut.security.token.jwt.signatures.jwks.typo.url", "http://localhost:8081/keys",
                "micronaut.security.token.jwt.signatures.jwks.typo.key-type", "RSAA"))) {
                context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("typo"));
            }
        });
        ConfigurationException cause = configurationException(e);
        assertNotNull(cause, () -> "expected a ConfigurationException cause but got " + e);
        assertTrue(cause.getMessage().contains("RSAA"), cause.getMessage());
    }

    @Nullable
    private static ConfigurationException configurationException(Throwable t) {
        for (Throwable cause = t; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConfigurationException) {
                return (ConfigurationException) cause;
            }
        }
        return null;
    }

    @Test
    void keyTypeIsCaseInsensitive() {
        try (ApplicationContext context = ApplicationContext.run(configuration(
            "micronaut.security.token.jwt.signatures.jwks.lower.url", "http://localhost:8081/keys",
            "micronaut.security.token.jwt.signatures.jwks.lower.key-type", "rsa"))) {
            assertEquals(KeyType.RSA, context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("lower")).getKeyType());
        }
    }

    @Test
    void keyTypeIsNotRestrictedUnlessConfigured() {
        try (ApplicationContext context = ApplicationContext.run(configuration(
            "micronaut.security.token.jwt.signatures.jwks.restricted.url", "http://localhost:8081/keys",
            "micronaut.security.token.jwt.signatures.jwks.restricted.key-type", "EC",
            "micronaut.security.token.jwt.signatures.jwks.unrestricted.url", "http://localhost:8082/keys"))) {
            assertEquals(KeyType.EC, context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("restricted")).getKeyType());
            assertNull(context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("unrestricted")).getKeyType());
        }
    }

    private static Map<String, Object> configuration(String... keyValues) {
        Map<String, Object> configuration = new HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            configuration.put(keyValues[i], keyValues[i + 1]);
        }
        return configuration;
    }

    private static JwksSignature signature(@Nullable KeyType keyType) {
        JwksSignatureConfigurationProperties configuration = new JwksSignatureConfigurationProperties();
        configuration.setUrl("http://localhost:8081/keys");
        configuration.setKeyType(keyType);
        return new JwksSignature(configuration, new DefaultJwkValidator(), new StaticJwkSetFetcher());
    }

    private static boolean verify(JwksSignature signature, SignedJWT jwt) {
        try {
            return signature.verify(jwt);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignedJWT rsaSignedJwt() {
        try {
            return signedJwt(JWSAlgorithm.RS256, RSA_KEY.getKeyID(), new RSASSASigner(RSA_KEY));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignedJWT ecSignedJwt() {
        try {
            return signedJwt(JWSAlgorithm.ES256, EC_KEY.getKeyID(), new ECDSASigner(EC_KEY));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignedJWT signedJwt(JWSAlgorithm algorithm, String keyId, JWSSigner signer) throws JOSEException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("sherlock").build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(algorithm).keyID(keyId).build(), claims);
        jwt.sign(signer);
        return jwt;
    }

    private static RSAKey generateRsaKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-fixture-rsa-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ECKey generateEcKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("test-fixture-ec-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class StaticJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        @Override
        public Optional<JWKSet> fetch(@Nullable String url) {
            return Optional.of(JWK_SET);
        }

        @Override
        public void clearCache(String url) {
        }
    }
}
