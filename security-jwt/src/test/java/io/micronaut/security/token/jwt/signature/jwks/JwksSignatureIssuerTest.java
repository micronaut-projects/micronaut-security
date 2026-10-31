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
package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.inject.qualifiers.Qualifiers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A {@link JwksSignature} bound to an issuer only verifies tokens carrying that issuer.
 */
class JwksSignatureIssuerTest {
    private static final String ISSUER = "https://idp.example.com/oauth2/default";
    private static final RSAKey KEY = generateKey();

    @ParameterizedTest
    @ValueSource(strings = {
        "https://idp.example.com/oauth2/default",
        "https://idp.example.com/oauth2/default/",
        "HTTPS://idp.example.com/oauth2/default"
    })
    void tokenIssuedByTheBoundIssuerIsVerified(String iss) {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature(ISSUER, fetcher);
        assertTrue(verify(signature, signedJwt(new JWTClaimsSet.Builder().issuer(iss).subject("sherlock"))));
        assertEquals(1, fetcher.fetches.get());
    }

    @Test
    void tokenIssuedByAnotherIssuerIsNotVerifiedEvenIfSignedWithAKeyOfTheSet() {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature(ISSUER, fetcher);
        SignedJWT jwt = signedJwt(new JWTClaimsSet.Builder().issuer("https://other-idp.example.com/oauth2/default").subject("mallory"));
        assertFalse(verify(signature, jwt));
        assertEquals(0, fetcher.fetches.get(), "the key set must not be consulted for a token of another issuer");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "",
        "/",
        "https://",
        "com",
        "example.com",
        "idp.example.com",
        "oauth2/default",
        "default",
        "t",
        "evil-idp.example.com/oauth2/default",
        "https://evil-idp.example.com/oauth2/default",
        "http://idp.example.com/oauth2/default",
        "https://idp.example.com/oauth2/default/extra",
        "https://idp.example.com:443/oauth2/default",
        "https://idp.example.com/oauth2/default//",
        " https://idp.example.com/oauth2/default"
    })
    void suffixesAndEmptyIssuerAreNotVerified(String iss) {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature(ISSUER, fetcher);
        assertFalse(verify(signature, signedJwt(new JWTClaimsSet.Builder().issuer(iss).subject("mallory"))));
        assertEquals(0, fetcher.fetches.get());
    }

    @Test
    void setBoundToABlankIssuerFailsClosed() {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature("/", fetcher);
        assertFalse(verify(signature, signedJwt(new JWTClaimsSet.Builder().issuer("").subject("mallory"))));
        assertFalse(verify(signature, signedJwt(new JWTClaimsSet.Builder().issuer("/").subject("mallory"))));
    }

    @Test
    void tokenWithoutIssuerIsNotVerifiedWhenTheSetIsBoundToAnIssuer() {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature(ISSUER, fetcher);
        assertFalse(verify(signature, signedJwt(new JWTClaimsSet.Builder().subject("mallory"))));
        assertEquals(0, fetcher.fetches.get());
    }

    @Test
    void setNotBoundToAnIssuerVerifiesTokensOfAnyIssuer() {
        CountingJwkSetFetcher fetcher = new CountingJwkSetFetcher();
        JwksSignature signature = signature(null, fetcher);
        assertTrue(verify(signature, signedJwt(new JWTClaimsSet.Builder().issuer("https://other-idp.example.com").subject("sherlock"))));
        assertTrue(verify(signature, signedJwt(new JWTClaimsSet.Builder().subject("sherlock"))));
    }

    @Test
    void issuerCanBeBoundViaConfiguration() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.token.jwt.signatures.jwks.bound.url", "http://localhost:8081/keys");
        configuration.put("micronaut.security.token.jwt.signatures.jwks.bound.issuer", ISSUER);
        configuration.put("micronaut.security.token.jwt.signatures.jwks.unbound.url", "http://localhost:8082/keys");
        try (ApplicationContext context = ApplicationContext.run(configuration)) {
            assertEquals(ISSUER, context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("bound")).getIssuer());
            assertNull(context.getBean(JwksSignatureConfiguration.class, Qualifiers.byName("unbound")).getIssuer());
        }
    }

    private static JwksSignature signature(@Nullable String issuer, JwkSetFetcher<JWKSet> fetcher) {
        JwksSignatureConfigurationProperties configuration = new JwksSignatureConfigurationProperties();
        configuration.setUrl("http://localhost:8081/keys");
        configuration.setIssuer(issuer);
        return new JwksSignature(configuration, new DefaultJwkValidator(), fetcher);
    }

    private static boolean verify(JwksSignature signature, SignedJWT jwt) {
        try {
            return signature.verify(jwt);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SignedJWT signedJwt(JWTClaimsSet.Builder claims) {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY.getKeyID()).build(), claims.build());
        try {
            jwt.sign(new RSASSASigner(KEY));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt;
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-fixture-key").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class CountingJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        private final AtomicInteger fetches = new AtomicInteger();

        @Override
        public Optional<JWKSet> fetch(@Nullable String url) {
            fetches.incrementAndGet();
            return Optional.of(new JWKSet(KEY.toPublicJWK()));
        }

        @Override
        public void clearCache(String url) {
        }
    }
}
