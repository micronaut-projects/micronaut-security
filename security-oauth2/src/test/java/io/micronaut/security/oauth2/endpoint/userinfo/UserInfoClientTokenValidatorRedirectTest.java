package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
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
 * The HTTP client used to talk to the UserInfo endpoint must not follow redirects. Otherwise a malicious
 * or compromised provider can make the application send the bearer token to any address it can reach and
 * treat the JSON found there as the claims of the authenticated user.
 */
class UserInfoClientTokenValidatorRedirectTest {

    private static final String REDIRECT_TOKEN = "redirect-token-fixture-not-a-secret";
    private static final String VALID_TOKEN = "valid-token-fixture-not-a-secret";

    @Test
    void userInfoClientDoesNotFollowRedirects() {
        try (EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "UserInfoClientTokenValidatorRedirectTestProvider"))) {
            RequestCounter counter = provider.getApplicationContext().getBean(RequestCounter.class);
            Map<String, Object> config = Map.of(
                "spec.name", "UserInfoClientTokenValidatorRedirectTest",
                "micronaut.security.oauth2.clients.authserver.client-id", "client-id-fixture",
                "micronaut.security.oauth2.clients.authserver.client-secret", "client-secret-fixture-not-a-secret",
                "micronaut.security.oauth2.clients.authserver.openid.issuer", provider.getURL().toString());
            try (ApplicationContext ctx = ApplicationContext.run(config)) {
                UserInfoClientTokenValidator validator = ctx.getBean(UserInfoClientTokenValidator.class);
                assertEquals("authserver", validator.getName());

                // rejected path: the UserInfo endpoint redirects to an internal address
                Optional<Authentication> redirected = Mono.from(validator.validateToken(REDIRECT_TOKEN, null)).blockOptional();
                assertTrue(redirected.isEmpty(), "Claims obtained by following a redirect must not authenticate the user");
                assertEquals(0, counter.internalRequests.get(), "The redirect target must not be requested");

                // accepted path: the UserInfo endpoint answers directly
                Optional<Authentication> authentication = Mono.from(validator.validateToken(VALID_TOKEN, null)).blockOptional();
                assertTrue(authentication.isPresent());
                assertEquals("user-fixture", authentication.get().getName());
                assertEquals(0, counter.internalRequests.get());
            }
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorRedirectTestProvider")
    @Singleton
    static class RequestCounter {
        final AtomicInteger internalRequests = new AtomicInteger();
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorRedirectTestProvider")
    @Controller
    static class ProviderController {
        private final RequestCounter counter;
        private final EmbeddedServer embeddedServer;

        ProviderController(RequestCounter counter, EmbeddedServer embeddedServer) {
            this.counter = counter;
            this.embeddedServer = embeddedServer;
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        Map<String, Object> configuration() {
            String baseUrl = embeddedServer.getURL().toString();
            return Map.of(
                "issuer", baseUrl,
                "authorization_endpoint", baseUrl + "/oauth/authorize",
                "token_endpoint", baseUrl + "/oauth/token",
                "jwks_uri", baseUrl + "/jwks",
                "userinfo_endpoint", baseUrl + "/userinfo");
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> userinfo(@Header String authorization) {
            if (authorization.equals("Bearer " + REDIRECT_TOKEN)) {
                return HttpResponse.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, embeddedServer.getURL() + "/internal/userinfo");
            }
            if (authorization.equals("Bearer " + VALID_TOKEN)) {
                return HttpResponse.ok(Map.of("sub", "user-fixture"));
            }
            return HttpResponse.unauthorized();
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/internal/userinfo")
        Map<String, Object> internalUserinfo() {
            counter.internalRequests.incrementAndGet();
            return Map.of("sub", "internal-user-fixture");
        }
    }
}
