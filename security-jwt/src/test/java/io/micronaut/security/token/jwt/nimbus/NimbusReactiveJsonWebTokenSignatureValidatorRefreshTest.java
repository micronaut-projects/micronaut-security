package io.micronaut.security.token.jwt.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.DefaultJwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NimbusReactiveJsonWebTokenSignatureValidatorRefreshTest {
    private static final RSAKey CACHED_KEY = generateKey("cached");
    private static final RSAKey ROTATED_KEY = generateKey("rotated");

    @Test
    void tokenWithKeyIdIsVerifiedOnceIfNoJwksConfigurationCanRefresh() {
        RejectingSignatureConfiguration rejecting = new RejectingSignatureConfiguration();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(rejecting));

        assertFalse(validate(validator, signedJwt(ROTATED_KEY, ROTATED_KEY.getKeyID())));
        assertEquals(1, rejecting.verifications.get());
    }

    @Test
    void tokenWhoseKeyIdIsCachedButWhoseSignatureIsInvalidIsVerifiedOnceAndDoesNotRefresh() {
        RejectingSignatureConfiguration rejecting = new RejectingSignatureConfiguration();
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(rejecting, jwksSignature(fetcher)));

        assertFalse(validate(validator, signedJwt(ROTATED_KEY, CACHED_KEY.getKeyID())));
        assertEquals(1, rejecting.verifications.get());
        assertEquals(1, fetcher.fetches.get());
        assertEquals(0, fetcher.refreshes.get());
    }

    @Test
    void tokenWhoseKeyIdIsNotCachedIsVerifiedAgainWithARefresh() {
        RejectingSignatureConfiguration rejecting = new RejectingSignatureConfiguration();
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher();
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(rejecting, jwksSignature(fetcher)));

        assertTrue(validate(validator, signedJwt(ROTATED_KEY, ROTATED_KEY.getKeyID())));
        assertEquals(1, fetcher.refreshes.get());
    }

    @Test
    void tokenVerifiedByAnotherConfigurationDoesNotRefresh() {
        StubJwkSetFetcher fetcher = new StubJwkSetFetcher();
        ReactiveSignatureConfiguration<SignedJWT> accepting = jwt -> Mono.just(true);
        NimbusReactiveJsonWebTokenSignatureValidator validator = new NimbusReactiveJsonWebTokenSignatureValidator(List.of(), List.of(jwksSignature(fetcher), accepting));

        assertTrue(validate(validator, signedJwt(ROTATED_KEY, ROTATED_KEY.getKeyID())));
        assertEquals(0, fetcher.refreshes.get());
    }

    private static boolean validate(NimbusReactiveJsonWebTokenSignatureValidator validator, SignedJWT jwt) {
        return Boolean.TRUE.equals(Mono.from(validator.validateSignature(jwt)).block());
    }

    private static ReactiveJwksSignature jwksSignature(JwkSetFetcher<JWKSet> fetcher) {
        JwksSignatureConfigurationProperties configuration = new JwksSignatureConfigurationProperties("test");
        configuration.setUrl("http://localhost:8081/keys");
        return new ReactiveJwksSignature(configuration, new DefaultJwkValidator(), fetcher);
    }

    private static SignedJWT signedJwt(RSAKey signingKey, String keyId) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                new JWTClaimsSet.Builder().subject("sherlock").build());
            jwt.sign(new RSASSASigner(signingKey));
            return jwt;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generateKey(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static final class RejectingSignatureConfiguration implements ReactiveSignatureConfiguration<SignedJWT> {
        private final AtomicInteger verifications = new AtomicInteger();

        @Override
        public Publisher<Boolean> verify(SignedJWT token) {
            verifications.incrementAndGet();
            return Mono.just(false);
        }
    }

    /**
     * Caches the key set with {@link #CACHED_KEY} and retrieves the one with {@link #ROTATED_KEY} when refreshed.
     */
    private static final class StubJwkSetFetcher implements JwkSetFetcher<JWKSet> {
        private final AtomicInteger fetches = new AtomicInteger();
        private final AtomicInteger refreshes = new AtomicInteger();

        @Override
        @NonNull
        public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
            fetches.incrementAndGet();
            return Mono.just(new JWKSet(CACHED_KEY.toPublicJWK()));
        }

        @Override
        @NonNull
        public Publisher<JWKSet> refresh(@Nullable String providerName, @NonNull String url) {
            refreshes.incrementAndGet();
            return Mono.just(new JWKSet(ROTATED_KEY.toPublicJWK()));
        }

        @Override
        public void clearCache(String url) {
        }
    }
}
