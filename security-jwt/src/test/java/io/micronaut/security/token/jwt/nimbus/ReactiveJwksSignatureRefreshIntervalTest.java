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
import io.micronaut.security.token.jwt.signature.jwks.JwksClientReactorContext;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfiguration;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Refreshes of the JWKS triggered by tokens with an unknown key ID are rate limited by
 * {@link JwksSignatureConfiguration#getRefreshInterval()}. The clock is controlled by the test, so nothing sleeps.
 */
class ReactiveJwksSignatureRefreshIntervalTest {

    private static final RSAKey KNOWN = generateKey("known");
    private static final SignedJWT UNKNOWN_KEY_ID_JWT = sign(generateKey("unknown"));

    @Test
    void jwksIsRefreshedAtMostOncePerRefreshInterval() {
        AtomicLong clock = new AtomicLong(Long.MAX_VALUE - 5);
        CountingJwks jwks = new CountingJwks();
        ReactiveJwksSignature signature = signature(Duration.ofSeconds(30), jwks, clock);

        assertFalse(verifyAllowingRefresh(signature));
        assertEquals(1, jwks.refreshes.get(), "the first refresh is allowed straight away");

        clock.addAndGet(Duration.ofSeconds(29).toNanos());
        assertFalse(verifyAllowingRefresh(signature));
        assertEquals(1, jwks.refreshes.get(), "no refresh within the interval, even if the clock wraps around");

        clock.addAndGet(Duration.ofSeconds(1).toNanos());
        assertFalse(verifyAllowingRefresh(signature));
        assertEquals(2, jwks.refreshes.get(), "the JWKS may be refreshed again once the interval elapses");
    }

    @Test
    void jwksIsNotRefreshedUnlessTheReactorContextAllowsIt() {
        CountingJwks jwks = new CountingJwks();
        ReactiveJwksSignature signature = signature(Duration.ofSeconds(30), jwks, new AtomicLong());
        JwksClientReactorContext context = new JwksClientReactorContext();

        assertFalse(verify(signature, context));

        assertEquals(0, jwks.refreshes.get());
        assertTrue(context.isKeyIdUnknown());
    }

    @Test
    void anIntervalTooLongToBeExpressedInNanosecondsDoesNotOverflow() {
        AtomicLong clock = new AtomicLong();
        CountingJwks jwks = new CountingJwks();
        ReactiveJwksSignature signature = signature(Duration.ofSeconds(Long.MAX_VALUE), jwks, clock);

        assertFalse(verifyAllowingRefresh(signature));
        clock.addAndGet(Duration.ofDays(365).toNanos());
        assertFalse(verifyAllowingRefresh(signature));

        assertEquals(1, jwks.refreshes.get());
    }

    @Test
    void aNegativeIntervalDisablesTheRateLimit() {
        CountingJwks jwks = new CountingJwks();
        ReactiveJwksSignature signature = signature(Duration.ofSeconds(-30), jwks, new AtomicLong());

        assertFalse(verifyAllowingRefresh(signature));
        assertFalse(verifyAllowingRefresh(signature));

        assertEquals(2, jwks.refreshes.get());
    }

    private static boolean verifyAllowingRefresh(ReactiveJwksSignature signature) {
        JwksClientReactorContext context = new JwksClientReactorContext();
        context.allowRefreshOnUnknownKeyId();
        return verify(signature, context);
    }

    private static boolean verify(ReactiveJwksSignature signature, JwksClientReactorContext context) {
        return Boolean.TRUE.equals(Mono.from(signature.verify(UNKNOWN_KEY_ID_JWT))
                .contextWrite(ctx -> ctx.put(JwksClientReactorContext.class, context))
                .block());
    }

    private static ReactiveJwksSignature signature(Duration refreshInterval, JwkSetFetcher<JWKSet> fetcher, AtomicLong clock) {
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
            public Duration getRefreshInterval() {
                return refreshInterval;
            }

            @Override
            public String getName() {
                return "rotating";
            }
        }, new DefaultJwkValidator(), fetcher, clock::get);
    }

    private static SignedJWT sign(RSAKey key) {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("sherlock").build());
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
     * A JWKS which never contains the key ID of the token and counts how often it is refreshed.
     */
    private static final class CountingJwks implements JwkSetFetcher<JWKSet> {
        private final AtomicInteger refreshes = new AtomicInteger();
        private final JWKSet jwkSet = new JWKSet(KNOWN.toPublicJWK());

        @Override
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            return Mono.just(jwkSet);
        }

        @Override
        public void clearCache(String url) {
            // nothing is cached
        }

        @Override
        public Publisher<JWKSet> refresh(@Nullable String providerName, String url) {
            refreshes.incrementAndGet();
            return Mono.just(jwkSet);
        }
    }
}
