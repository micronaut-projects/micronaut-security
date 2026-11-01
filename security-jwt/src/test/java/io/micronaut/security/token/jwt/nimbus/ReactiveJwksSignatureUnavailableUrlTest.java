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
package io.micronaut.security.token.jwt.nimbus;

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
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReactiveJwksSignatureUnavailableUrlTest {

    @Test
    void signatureIsNotVerifiedWhenTheJwksUrlCannotBeResolved() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").generate();
        ReactiveJwksSignature signature = signature(() -> {
            throw new IllegalStateException("provider metadata unavailable");
        }, key);
        assertEquals(Boolean.FALSE, Mono.from(signature.verify(signedJwt(key))).block());
    }

    @Test
    void signatureIsNotVerifiedWhenTheJwksUrlIsNull() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").generate();
        ReactiveJwksSignature signature = signature(() -> null, key);
        assertNull(Mono.from(signature.verify(signedJwt(key))).block());
    }

    @Test
    void signatureIsVerifiedWhenTheJwksUrlResolves() throws JOSEException {
        RSAKey key = new RSAKeyGenerator(2048).keyID("k").generate();
        ReactiveJwksSignature signature = signature(() -> "https://issuer.example/keys", key);
        assertEquals(Boolean.TRUE, Mono.from(signature.verify(signedJwt(key))).block());
    }

    private static ReactiveJwksSignature signature(Supplier<String> url, RSAKey key) {
        JwksSignatureConfiguration configuration = new JwksSignatureConfiguration() {
            @Override
            public @NonNull String getUrl() {
                return url.get();
            }

            @Override
            public @Nullable KeyType getKeyType() {
                return KeyType.RSA;
            }

            @Override
            @SuppressWarnings("removal")
            public @NonNull Integer getCacheExpiration() {
                return 60;
            }

            @Override
            public @NonNull String getName() {
                return "provider";
            }
        };
        JwkSetFetcher<JWKSet> fetcher = new JwkSetFetcher<>() {
            @Override
            public Optional<JWKSet> fetch(@Nullable String url) {
                return url == null ? Optional.empty() : Optional.of(new JWKSet(key.toPublicJWK()));
            }

            @Override
            public @NonNull Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
                return url == null ? Mono.empty() : Mono.just(new JWKSet(key.toPublicJWK()));
            }

            @Override
            public void clearCache(String url) {
            }
        };
        return new ReactiveJwksSignature(configuration, new DefaultJwkValidator(), fetcher);
    }

    private static SignedJWT signedJwt(RSAKey key) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
            new JWTClaimsSet.Builder().subject("alice").build());
        jwt.sign(new RSASSASigner(key));
        return jwt;
    }
}
