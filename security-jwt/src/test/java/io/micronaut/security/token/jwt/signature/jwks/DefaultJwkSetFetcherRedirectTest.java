package io.micronaut.security.token.jwt.signature.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link DefaultJwkSetFetcher} retrieves the JWK Set with the JDK {@code HttpURLConnection}, which follows redirects by
 * default. It must not: otherwise a malicious or compromised provider can make the application fetch any address it can
 * reach and treat the JSON found there as the keys that sign the tokens it accepts.
 */
class DefaultJwkSetFetcherRedirectTest {

    private static final String INTERNAL_KEY_ID = "internal-fixture";
    private static final String DIRECT_KEY_ID = "direct-fixture";

    @Test
    void defaultJwkSetFetcherDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "DefaultJwkSetFetcherRedirectTestProvider"))) {
            assertDoesNotFollowRedirects(provider, new DefaultJwkSetFetcher(new JwksClientConfigurationProperties()));
        }
    }

    /**
     * The {@link JwkSetFetcher} bean, which the JWKS signature configurations use, must not follow redirects either.
     */
    @Test
    void jwkSetFetcherBeanDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Collections.singletonMap("spec.name", "DefaultJwkSetFetcherRedirectTestProvider"))) {
            try (ApplicationContext ctx = ApplicationContext.run(Collections.singletonMap("spec.name", "DefaultJwkSetFetcherRedirectTest"))) {
                @SuppressWarnings("unchecked")
                JwkSetFetcher<JWKSet> fetcher = ctx.getBean(JwkSetFetcher.class);
                assertTrue(fetcher instanceof DefaultJwkSetFetcher);
                assertDoesNotFollowRedirects(provider, fetcher);
            }
        }
    }

    private static void assertDoesNotFollowRedirects(EmbeddedServer provider, JwkSetFetcher<JWKSet> fetcher) {
        RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);

        // rejected path: the JWKS url redirects to an internal address
        Optional<JWKSet> redirected = fetcher.fetch(provider.getURL() + "/jwks");
        assertFalse(redirected.isPresent(), "A redirect must not produce a JWK Set");
        assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");
        assertEquals(1, counter.redirectingRequests.get());

        // accepted path: a JWKS url which answers directly works
        Optional<JWKSet> direct = fetcher.fetch(provider.getURL() + "/direct/jwks");
        assertTrue(direct.isPresent());
        assertNotNull(direct.get().getKeyByKeyId(DIRECT_KEY_ID));
        assertNull(direct.get().getKeyByKeyId(INTERNAL_KEY_ID));
        assertEquals(0, counter.internalRequests.get());
    }

    private static String jwks(String keyId) {
        try {
            // JWKSet#toString serializes public keys only
            return new JWKSet(new RSAKeyGenerator(2048).keyID(keyId).generate().toPublicJWK()).toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Requires(property = "spec.name", value = "DefaultJwkSetFetcherRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger redirectingRequests = new AtomicInteger();
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "DefaultJwkSetFetcherRedirectTestProvider")
    @Controller
    static class ProviderController {
        private final RequestCounter counter;
        private final EmbeddedServer embeddedServer;

        ProviderController(RequestCounter counter, EmbeddedServer embeddedServer) {
            this.counter = counter;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/jwks")
        HttpResponse<?> redirectingJwks() {
            counter.redirectingRequests.incrementAndGet();
            return HttpResponse.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, embeddedServer.getURL() + "/internal/jwks");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.APPLICATION_JSON)
        @Get("/internal/jwks")
        String internalJwks() {
            counter.internalRequests.incrementAndGet();
            return jwks(INTERNAL_KEY_ID);
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Produces(MediaType.APPLICATION_JSON)
        @Get("/direct/jwks")
        String directJwks() {
            return jwks(DIRECT_KEY_ID);
        }
    }
}
