package io.micronaut.security.jwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.annotation.ServerFilter;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.http.filter.ServerFilterPhase;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.utils.SecurityService;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import io.micronaut.core.annotation.Nullable;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Two requests reach a {@code @Secured} expression endpoint while the remote JWK Set is being loaded.
 * The first one carries a valid token of a user for whom the expression is true. The second one carries either
 * a junk token with no account behind it or a valid token of a user for whom the expression is false.
 * Both wait for the same in-flight JWK Set load. The second request must be evaluated against its own
 * security context and rejected, never against the first user's context.
 * <p>
 * When both users are allowed, the rest of the filter chain and the route must also run in the context of their own
 * request: a filter placed right after the security filter, and the controller, must each see their own user.
 */
class SecuredExpressionJwksLoadTest {

    private static final String AUTH_SERVER_SPEC = "SecuredExpressionJwksLoadTestAuthServer";
    private static final String RESOURCE_SERVER_SPEC = "SecuredExpressionJwksLoadTest";

    @Test
    void junkTokenIsRejectedWhileAnotherUserLoadsTheJwks() throws Exception {
        assertRejectedWhileAnotherUserLoadsTheJwks("junk token with no account behind it", keys -> junkToken(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void userForWhomTheExpressionIsFalseIsRejectedWhileAnotherUserLoadsTheJwks() throws Exception {
        assertRejectedWhileAnotherUserLoadsTheJwks("valid token of a user for whom the expression is false",
            keys -> keys.sign("moriarty", "moriarty@micronaut.example"), HttpStatus.FORBIDDEN);
    }

    @Test
    void eachAllowedUserSeesOwnIdentityWhileSharingTheJwksLoad() throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER_SPEC))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            Map<String, Object> config = Map.of(
                "spec.name", RESOURCE_SERVER_SPEC,
                "micronaut.http.client.read-timeout", "30s",
                "micronaut.security.token.jwt.signatures.jwks.auth.url", "http://localhost:" + authServer.getPort() + "/keys");
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config);
                 HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                JwkSetFetcherLatch fetcherLatch = server.getApplicationContext().getBean(JwkSetFetcherLatch.class);
                String sherlockToken = keysController.sign("sherlock", "sherlock@micronaut.example");
                String watsonToken = keysController.sign("watson", "watson@micronaut.example");

                ExecutorService executor = Executors.newFixedThreadPool(2);
                try {
                    Future<HttpResponse<String>> sherlock = executor.submit(() ->
                        client.exchange(HttpRequest.GET("/whoami").bearerAuth(sherlockToken), String.class));
                    assertTrue(keysController.requested.await(30, TimeUnit.SECONDS), "the JWK Set was not requested");
                    Future<HttpResponse<String>> watson = executor.submit(() ->
                        client.exchange(HttpRequest.GET("/whoami").bearerAuth(watsonToken), String.class));
                    assertTrue(fetcherLatch.subscribed.await(30, TimeUnit.SECONDS), "the second request did not wait for the JWK Set");
                    keysController.release.countDown();

                    assertOwnIdentity("sherlock", sherlock.get(30, TimeUnit.SECONDS));
                    assertOwnIdentity("watson", watson.get(30, TimeUnit.SECONDS));
                } finally {
                    keysController.release.countDown();
                    executor.shutdownNow();
                }
            }
        }
    }

    private static void assertOwnIdentity(String expectedUser, HttpResponse<String> response) {
        assertEquals(HttpStatus.OK, response.status());
        assertEquals(expectedUser, response.header(FilterUserRecorder.HEADER), "user seen by the filter after the security filter proceeded");
        assertEquals(expectedUser, response.body(), "user seen by the controller");
    }

    private static void assertRejectedWhileAnotherUserLoadsTheJwks(String description,
                                                                   Function<KeysController, String> rejectedToken,
                                                                   HttpStatus expectedStatus) throws Exception {
        try (EmbeddedServer authServer = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", AUTH_SERVER_SPEC))) {
            KeysController keysController = authServer.getApplicationContext().getBean(KeysController.class);
            Map<String, Object> config = Map.of(
                "spec.name", RESOURCE_SERVER_SPEC,
                "micronaut.http.client.read-timeout", "30s",
                "micronaut.security.token.jwt.signatures.jwks.auth.url", "http://localhost:" + authServer.getPort() + "/keys");
            try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config);
                 HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                JwkSetFetcherLatch fetcherLatch = server.getApplicationContext().getBean(JwkSetFetcherLatch.class);
                String allowedToken = keysController.sign("sherlock", "sherlock@micronaut.example");
                String otherToken = rejectedToken.apply(keysController);

                ExecutorService executor = Executors.newFixedThreadPool(2);
                try {
                    Future<HttpResponse<String>> allowed = executor.submit(() ->
                        client.exchange(HttpRequest.GET("/secret").bearerAuth(allowedToken), String.class));
                    assertTrue(keysController.requested.await(30, TimeUnit.SECONDS), "the JWK Set was not requested");

                    Future<HttpStatus> rejected = executor.submit(() -> {
                        try {
                            HttpResponse<String> leaked = client.exchange(HttpRequest.GET("/secret").bearerAuth(otherToken), String.class);
                            return fail("the " + description + " was accepted with status " + leaked.status() + " and body " + leaked.body());
                        } catch (HttpClientResponseException e) {
                            return e.getStatus();
                        }
                    });
                    // wait until the second request is waiting for the in-flight JWK Set load before releasing it
                    assertTrue(fetcherLatch.subscribed.await(30, TimeUnit.SECONDS), "the second request did not wait for the JWK Set");
                    keysController.release.countDown();

                    HttpResponse<String> response = allowed.get(30, TimeUnit.SECONDS);
                    assertEquals(HttpStatus.OK, response.status());
                    assertEquals("sherlock", response.body());
                    assertEquals(expectedStatus, rejected.get(30, TimeUnit.SECONDS));
                } finally {
                    keysController.release.countDown();
                    executor.shutdownNow();
                }
            }
        }
    }

    private static String junkToken() {
        byte[] signature = new byte[256];
        Arrays.fill(signature, (byte) 1);
        return Base64URL.encode("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8))
            + "." + Base64URL.encode("{\"sub\":\"nobody\"}".getBytes(StandardCharsets.UTF_8))
            + "." + Base64URL.encode(signature);
    }

    @Requires(property = "spec.name", value = AUTH_SERVER_SPEC)
    @Controller("/keys")
    static class KeysController {
        final CountDownLatch requested = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        private final RSAKey rsaKey;

        KeysController() throws JOSEException {
            this.rsaKey = new RSAKeyGenerator(2048)
                .algorithm(JWSAlgorithm.RS256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("test-fixture-key")
                .generate();
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @ExecuteOn(TaskExecutors.BLOCKING)
        @Produces(MediaType.APPLICATION_JSON)
        @Get
        String keys() throws InterruptedException {
            requested.countDown();
            release.await(30, TimeUnit.SECONDS);
            return new JWKSet(rsaKey.toPublicJWK()).toString();
        }

        String sign(String subject, String email) {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .claim("email", email)
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claims);
            try {
                jwt.sign(new RSASSASigner(rsaKey));
            } catch (JOSEException e) {
                throw new IllegalStateException("could not sign the test token", e);
            }
            return jwt.serialize();
        }
    }

    /**
     * Signals when two requests are waiting for the JWK Set.
     */
    @Requires(property = "spec.name", value = RESOURCE_SERVER_SPEC)
    @Singleton
    static class JwkSetFetcherLatch implements BeanCreatedEventListener<JwkSetFetcher<JWKSet>> {
        final CountDownLatch subscribed = new CountDownLatch(2);

        @Override
        public JwkSetFetcher<JWKSet> onCreated(BeanCreatedEvent<JwkSetFetcher<JWKSet>> event) {
            JwkSetFetcher<JWKSet> delegate = event.getBean();
            return new JwkSetFetcher<>() {
                @Override
                public Optional<JWKSet> fetch(@Nullable String url) {
                    return delegate.fetch(url);
                }

                @Override
                public Publisher<JWKSet> fetch(@Nullable String providerName, @Nullable String url) {
                    return Flux.from(delegate.fetch(providerName, url)).doOnSubscribe(subscription -> subscribed.countDown());
                }

                @Override
                public void clearCache(String url) {
                    delegate.clearCache(url);
                }
            };
        }
    }

    /**
     * Runs right after the security filter proceeds with the chain, before the route is executed, and records the
     * user resolved through the thread-bound security context at that point. The route execution binds the request
     * again on its own, so only a filter at this position observes the context the security filter proceeded with.
     */
    @Requires(property = "spec.name", value = RESOURCE_SERVER_SPEC)
    @ServerFilter("/whoami")
    static class FilterUserRecorder implements Ordered {
        static final String ATTRIBUTE = "whoami.filter-user";
        static final String HEADER = "X-Filter-User";
        private final SecurityService securityService;

        FilterUserRecorder(SecurityService securityService) {
            this.securityService = securityService;
        }

        @Override
        public int getOrder() {
            return ServerFilterPhase.SECURITY.after();
        }

        @RequestFilter
        void record(HttpRequest<?> request) {
            request.setAttribute(ATTRIBUTE, securityService.username().orElse("anonymous"));
        }
    }

    @Requires(property = "spec.name", value = RESOURCE_SERVER_SPEC)
    @Controller("/whoami")
    static class WhoAmIController {
        private final SecurityService securityService;

        WhoAmIController(SecurityService securityService) {
            this.securityService = securityService;
        }

        @Secured("#{ user != null }")
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        HttpResponse<String> whoAmI(HttpRequest<?> request) {
            return HttpResponse.ok(securityService.username().orElse("anonymous"))
                .header(FilterUserRecorder.HEADER, request.getAttribute(FilterUserRecorder.ATTRIBUTE, String.class).orElse("none"));
        }
    }

    @Requires(property = "spec.name", value = RESOURCE_SERVER_SPEC)
    @Controller("/secret")
    static class SecretController {

        @Secured("#{ user?.attributes?.get('email') == 'sherlock@micronaut.example' }")
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String secret(@Nullable Principal principal) {
            return principal == null ? "anonymous" : principal.getName();
        }
    }
}
