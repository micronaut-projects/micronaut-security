package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
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

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The HTTP client used to fetch a JWK Set must not follow redirects. Otherwise a malicious or compromised
 * provider can make the application fetch any address it can reach and treat the JSON found there as the
 * keys that sign the tokens it accepts.
 */
class HttpClientJwksClientRedirectTest {

    private static final String INTERNAL_JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"internal-fixture\"}]}";
    private static final String DIRECT_JWKS = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"direct-fixture\"}]}";

    @Test
    void jwksClientDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "HttpClientJwksClientRedirectTestProvider"))) {
            RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);
            try (ApplicationContext ctx = ApplicationContext.run(Map.of("spec.name", "HttpClientJwksClientRedirectTest"))) {
                JwksClient jwksClient = ctx.getBean(HttpClientJwksClient.class);

                // rejected path: the JWKS url redirects to an internal address
                Optional<String> redirected = Mono.from(jwksClient.load(null, provider.getURL() + "/jwks")).blockOptional();
                assertTrue(redirected.isEmpty() || !redirected.get().contains("internal-fixture"),
                    "A JWK Set obtained by following a redirect must not be used");
                assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");

                // accepted path: a JWKS url which answers directly works
                Optional<String> direct = Mono.from(jwksClient.load(null, provider.getURL() + "/direct/jwks")).blockOptional();
                assertTrue(direct.isPresent());
                assertEquals(DIRECT_JWKS, direct.get());
                assertEquals(0, counter.internalRequests.get());
            }
        }
    }

    @Test
    void namedServiceClientDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "HttpClientJwksClientRedirectTestProvider"))) {
            RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);
            try (ApplicationContext ctx = ApplicationContext.run(Map.of(
                "spec.name", "HttpClientJwksClientRedirectTest",
                "micronaut.http.services.myjwks.url", provider.getURL().toString(),
                "micronaut.http.services.myjwks.follow-redirects", "true"))) {
                JwksClient jwksClient = ctx.getBean(HttpClientJwksClient.class);

                Optional<String> redirected = Mono.from(jwksClient.load("myjwks", provider.getURL() + "/jwks")).blockOptional();
                assertTrue(redirected.isEmpty() || !redirected.get().contains("internal-fixture"));
                assertEquals(0, counter.internalRequests.get());

                Optional<String> direct = Mono.from(jwksClient.load("myjwks", provider.getURL() + "/direct/jwks")).blockOptional();
                assertEquals(DIRECT_JWKS, direct.orElse(null));
            }
        }
    }

    @Requires(property = "spec.name", value = "HttpClientJwksClientRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "HttpClientJwksClientRedirectTestProvider")
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
