package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ResourceRetrieverJwksClient}, the JWKS client used when the Micronaut HTTP client is not available, retrieves
 * the JWK Set with the JDK {@code HttpURLConnection}, which follows redirects by default. It must not: otherwise a
 * malicious or compromised provider can make the application fetch any address it can reach and treat the JSON found
 * there as the keys that sign the tokens it accepts.
 */
class ResourceRetrieverJwksClientRedirectTest {

    private static final String INTERNAL_JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"internal-fixture\"}]}";
    private static final String DIRECT_JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"direct-fixture\"}]}";

    @Test
    void resourceRetrieverJwksClientDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "ResourceRetrieverJwksClientRedirectTestProvider"))) {
            assertDoesNotFollowRedirects(provider, new ResourceRetrieverJwksClient(Schedulers.immediate()));
        }
    }

    /**
     * With the Micronaut HTTP client disabled for JWKS retrieval, the {@link JwksClient} bean is the
     * {@link ResourceRetrieverJwksClient}, and it must not follow redirects either.
     */
    @Test
    void jwksClientBeanDoesNotFollowRedirectsWhenHttpClientIsDisabled() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "ResourceRetrieverJwksClientRedirectTestProvider"))) {
            try (ApplicationContext ctx = ApplicationContext.run(Map.of(
                "spec.name", "ResourceRetrieverJwksClientRedirectTest",
                "micronaut.security.token.jwt.signatures.jwks-client.http-client.enabled", StringUtils.FALSE))) {
                JwksClient jwksClient = ctx.getBean(JwksClient.class);
                assertInstanceOf(ResourceRetrieverJwksClient.class, jwksClient);
                assertDoesNotFollowRedirects(provider, jwksClient);
            }
        }
    }

    private static void assertDoesNotFollowRedirects(EmbeddedServer provider, JwksClient jwksClient) {
        RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);

        // rejected path: the JWKS url redirects to an internal address
        Optional<String> redirected = Mono.from(jwksClient.load(null, provider.getURL() + "/jwks")).blockOptional();
        assertTrue(redirected.isEmpty(), "A redirect must not produce a JWK Set");
        assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");
        assertEquals(1, counter.redirectingRequests.get());

        // accepted path: a JWKS url which answers directly works
        Optional<String> direct = Mono.from(jwksClient.load(null, provider.getURL() + "/direct/jwks")).blockOptional();
        assertEquals(DIRECT_JWKS, direct.orElse(null));
        assertEquals(0, counter.internalRequests.get());
    }

    @Requires(property = "spec.name", value = "ResourceRetrieverJwksClientRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger redirectingRequests = new AtomicInteger();
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "ResourceRetrieverJwksClientRedirectTestProvider")
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
        @Get("/internal/jwks")
        String internalJwks() {
            counter.internalRequests.incrementAndGet();
            return INTERNAL_JWKS;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/direct/jwks")
        String directJwks() {
            return DIRECT_JWKS;
        }
    }
}
