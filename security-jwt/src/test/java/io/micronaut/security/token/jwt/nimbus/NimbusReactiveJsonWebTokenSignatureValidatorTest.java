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
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A token which no signature configuration verifies is only verified a second time, allowing a JWKS refresh, if a
 * JWKS reported that it does not know the key ID of the token. Otherwise an unverifiable token would cost twice
 * the signature verifications for nothing.
 */
class NimbusReactiveJsonWebTokenSignatureValidatorTest {

    private static final RSAKey CURRENT = generateKey("current");
    private static final RSAKey ROTATED = generateKey("rotated");

    @Test
    void tokenWithAKeyIdIsVerifiedOnceIfThereIsNoJwks() {
        CountingSignature other = new CountingSignature();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(other));

        assertNull(validate(validator, sign(ROTATED)));

        assertEquals(1, other.verifications.get());
    }

    @Test
    void tokenWithAKnownKeyIdAndAnInvalidSignatureIsVerifiedOnceAndDoesNotRefreshTheJwks() {
        CountingSignature other = new CountingSignature();
        RotatingJwks jwks = new RotatingJwks();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(other, jwksSignature(jwks)));

        assertNull(validate(validator, sign(generateKey(CURRENT.getKeyID()))));

        assertEquals(1, other.verifications.get());
        assertEquals(1, jwks.fetches.get());
        assertEquals(0, jwks.refreshes.get());
    }

    @Test
    void tokenWithAnUnknownKeyIdIsVerifiedAgainRefreshingTheJwks() {
        CountingSignature other = new CountingSignature();
        RotatingJwks jwks = new RotatingJwks();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(other, jwksSignature(jwks)));

        assertTrue(validate(validator, sign(ROTATED)));

        assertEquals(2, other.verifications.get());
        assertEquals(1, jwks.refreshes.get());
    }

    @Test
    void tokenWithoutKeyIdIsVerifiedOnce() {
        CountingSignature other = new CountingSignature();
        RotatingJwks jwks = new RotatingJwks();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(other, jwksSignature(jwks)));

        assertNull(validate(validator, sign(ROTATED, false)));

        assertEquals(1, other.verifications.get());
        assertEquals(0, jwks.refreshes.get());
    }

    @Nullable
    private static Boolean validate(NimbusReactiveJsonWebTokenSignatureValidator validator, SignedJWT jwt) {
        return Mono.from(validator.validateSignature(jwt)).block();
    }

    private static ReactiveJwksSignature jwksSignature(JwkSetFetcher<JWKSet> fetcher) {
        return new ReactiveJwksSignature(new JwksSignatureConfiguration() {
            @Override
            public String getUrl() {
                return "https://example.com/.well-known/jwks.json";
            }

            @Override
            public KeyType getKeyType() {
                return KeyType.RSA;
            }

            @Override
            public Integer getCacheExpiration() {
                return 60;
            }

            @Override
            public String getName() {
                return "rotating";
            }
        }, new DefaultJwkValidator(), fetcher);
    }

    private static SignedJWT sign(RSAKey key) {
        return sign(key, true);
    }

    private static SignedJWT sign(RSAKey key, boolean includeKeyId) {
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (includeKeyId) {
            header.keyID(key.getKeyID());
        }
        SignedJWT jwt = new SignedJWT(header.build(), new JWTClaimsSet.Builder().subject("sherlock").build());
        try {
            jwt.sign(new RSASSASigner(key));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        return jwt;
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).algorithm(JWSAlgorithm.RS256).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A signature configuration which verifies nothing and counts how often it is asked.
     */
    private static final class CountingSignature implements ReactiveSignatureConfiguration<SignedJWT> {
        private final AtomicInteger verifications = new AtomicInteger();

        @Override
        public Publisher<Boolean> verify(SignedJWT token) {
            verifications.incrementAndGet();
            return Mono.just(false);
        }
    }

    /**
     * Serves the JWKS with the current key until it is refreshed, and the JWKS with the rotated key afterwards.
     */
    private static final class RotatingJwks implements JwkSetFetcher<JWKSet> {
        private final AtomicInteger fetches = new AtomicInteger();
        private final AtomicInteger refreshes = new AtomicInteger();
        private volatile JWKSet jwkSet = new JWKSet(CURRENT.toPublicJWK());

        @Override
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            fetches.incrementAndGet();
            return Mono.just(jwkSet);
        }

        @Override
        public void clearCache(String url) {
            // nothing is cached
        }

        @Override
        public Publisher<JWKSet> refresh(@Nullable String providerName, String url) {
            refreshes.incrementAndGet();
            jwkSet = new JWKSet(ROTATED.toPublicJWK());
            return Mono.just(jwkSet);
        }
    }
}
