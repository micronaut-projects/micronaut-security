/*
 * Copyright 2026 original authors
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
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A {@link JwksSignatureConfiguration} which cannot resolve its url yet (for example, the {@code jwks_uri} of an OpenID
 * provider whose discovery document is not available) must fail the verification instead of failing the request.
 */
class JwksSignatureUnavailableUrlTest {

    @Test
    void signatureIsNotVerifiedWhenTheJwksUrlCannotBeResolved() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").algorithm(JWSAlgorithm.RS256).generate();
        JwksSignature signature = signature(() -> {
            throw new IllegalStateException("provider metadata unavailable");
        }, key);
        assertFalse(signature.verify(signedJwt(key)));
        assertFalse(signature.supports(JWSAlgorithm.RS256));
        assertFalse(signature.isPresent());
        assertDoesNotThrow(signature::clear);
    }

    @Test
    void signatureIsNotVerifiedWhenTheJwksUrlIsNull() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").algorithm(JWSAlgorithm.RS256).generate();
        JwksSignature signature = signature(() -> null, key);
        assertFalse(signature.verify(signedJwt(key)));
    }

    @Test
    void signatureIsVerifiedWhenTheJwksUrlResolves() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").algorithm(JWSAlgorithm.RS256).generate();
        JwksSignature signature = signature(() -> "https://issuer.example/keys", key);
        assertTrue(signature.verify(signedJwt(key)));
        assertTrue(signature.supports(JWSAlgorithm.RS256));
    }

    private static JwksSignature signature(Supplier<String> url, RSAKey key) {
        JwksSignatureConfiguration configuration = new JwksSignatureConfiguration() {
            @Override
            @NonNull
            public String getUrl() {
                return url.get();
            }

            @Override
            @Nullable
            public KeyType getKeyType() {
                return KeyType.RSA;
            }

            @Override
            @NonNull
            public Integer getCacheExpiration() {
                return 60;
            }
        };
        JwkSetFetcher<JWKSet> fetcher = new JwkSetFetcher<JWKSet>() {
            @Override
            @NonNull
            public Optional<JWKSet> fetch(@Nullable String url) {
                return url == null ? Optional.empty() : Optional.of(new JWKSet(key.toPublicJWK()));
            }

            @Override
            public void clearCache(String url) {
            }
        };
        return new JwksSignature(configuration, new DefaultJwkValidator(), fetcher);
    }

    private static SignedJWT signedJwt(RSAKey key) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
            new JWTClaimsSet.Builder().subject("alice").build());
        jwt.sign(new RSASSASigner(key));
        return jwt;
    }
}
