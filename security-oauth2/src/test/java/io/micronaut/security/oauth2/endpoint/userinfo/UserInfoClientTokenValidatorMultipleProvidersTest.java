package io.micronaut.security.oauth2.endpoint.userinfo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With several OpenID providers configured, a bearer token must only reach the UserInfo endpoint of the provider
 * which issued it. Forwarding it to the other providers leaks a live access token to a third party.
 */
class UserInfoClientTokenValidatorMultipleProvidersTest {
    private static final String OPAQUE_TOKEN = "opaque-test-fixture-not-a-secret";
    // Throwaway HMAC key. The resource server never knows it, so local JWT validation always fails
    // and the token falls through to the UserInfo validators.
    private static final byte[] NOT_A_SECRET = "test-fixture-not-a-secret-test-fixture-not-a-secret".getBytes(StandardCharsets.UTF_8);

    private EmbeddedServer providerA;
    private EmbeddedServer providerB;

    @BeforeEach
    void startProviders() {
        providerA = startProvider("provider-a");
        providerB = startProvider("provider-b");
    }

    @AfterEach
    void stopProviders() {
        providerA.close();
        providerB.close();
    }

    @Test
    void jwtIsOnlyForwardedToTheProviderMatchingItsIssuer() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String tokenForA = signedJwt(issuer(providerA), "alice");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForA)));
            assertEquals("provider-a:alice", username);
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB), "provider B must never see a token issued by provider A");

            String tokenForB = signedJwt(issuer(providerB), "bob");
            username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForB)));
            assertEquals("provider-b:bob", username);
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA), "provider A must never see a token issued by provider B");
            assertEquals(List.of(tokenForB), tokensReceivedBy(providerB));
        }
    }

    @Test
    void jwtFromAnUnknownIssuerIsNotForwardedToAnyProvider() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String foreignToken = signedJwt("https://idp.example.org/", "mallory");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(foreignToken)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void jwtWithoutIssuerIsNotForwardedToAnyProvider() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String noIssuer = signedJwt(null, "nobody");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(noIssuer)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());

            assertEquals(List.of(), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void opaqueTokenIsNotForwardedWhenSeveralProvidersExposeUserInfo() {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void opaqueTokenIsForwardedOnlyToProvidersOptedIn() {
        Map<String, Object> config = Map.of("micronaut.security.oauth2.clients.provider-a.openid.user-info.validate-opaque-tokens", true);
        try (EmbeddedServer server = startResourceServer(config)) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals("provider-a:" + OPAQUE_TOKEN, username);
            assertEquals(List.of(OPAQUE_TOKEN), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB), "provider B did not opt in and must not receive opaque tokens");
        }
    }

    @Test
    void jwtWithForeignIssuerIsNotForwardedEvenIfProviderAcceptsOpaqueTokens() throws Exception {
        Map<String, Object> config = Map.of("micronaut.security.oauth2.clients.provider-a.openid.user-info.validate-opaque-tokens", true);
        try (EmbeddedServer server = startResourceServer(config)) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String tokenForB = signedJwt(issuer(providerB), "bob");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForB)));
            assertEquals("provider-b:bob", username);
            assertEquals(List.of(), tokensReceivedBy(providerA));
            assertEquals(List.of(tokenForB), tokensReceivedBy(providerB));
        }
    }

    @Test
    void discoveryDocumentCannotClaimTheIssuerOfAnotherProvider() throws Exception {
        // Provider B's discovery document announces provider A's issuer. The configured issuer wins.
        providerB.getApplicationContext().getBean(FakeProvider.class).announcedIssuer = issuer(providerA);
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String tokenForA = signedJwt(issuer(providerA), "alice");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForA)));
            assertEquals("provider-a:alice", username);
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB), "provider B must not receive tokens issued by provider A");
        }
    }

    @Test
    void jwtWithIssuerDifferingOnlyInSchemeIsNotForwarded() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String httpsIssuer = issuer(providerA).replaceFirst("^http://", "https://");
            String lookalike = signedJwt(httpsIssuer, "mallory");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(lookalike)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA), "an iss claim with a different scheme is a different issuer");
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void issuerIdentifierIsTheExpectedIssuerWhenConfigured() throws Exception {
        // Provider A fetches discovery over one URL but issues tokens with another iss (e.g. Oracle IDCS, or an internal discovery URL)
        String publicIssuer = "https://public.example.org/realms/a";
        Map<String, Object> config = Map.of("micronaut.security.oauth2.clients.provider-a.openid.issuer-identifier", publicIssuer);
        try (EmbeddedServer server = startResourceServer(config)) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String tokenForA = signedJwt(publicIssuer, "alice");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForA)));
            assertEquals("provider-a:alice", username);
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));

            String discoveryUrlAsIssuer = signedJwt(issuer(providerA), "alice");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(discoveryUrlAsIssuer)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA), "once issuer-identifier is set, the discovery URL is no longer an accepted iss");
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void jwtWithIssuerSharingOnlyASuffixIsNotForwarded() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String lookalike = signedJwt("https://evil.example.org/" + issuer(providerA), "mallory");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(lookalike)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void jwtOfAnIssuerSharedBySeveralProvidersIsNotForwardedWithoutOptIn() throws Exception {
        // Two tenants of one provider (e.g. Oracle IDCS) issue tokens with the same provider wide iss but have distinct UserInfo endpoints
        String sharedIssuer = "https://identity.example.org/";
        Map<String, Object> config = Map.of(
            "micronaut.security.oauth2.clients.provider-a.openid.issuer-identifier", sharedIssuer,
            "micronaut.security.oauth2.clients.provider-b.openid.issuer-identifier", sharedIssuer);
        Logger factoryLogger = (Logger) LoggerFactory.getLogger(UserInfoClientFactory.class);
        ListAppender<ILoggingEvent> logEvents = new ListAppender<>();
        logEvents.start();
        factoryLogger.addAppender(logEvents);
        try (EmbeddedServer server = startResourceServer(config)) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String token = signedJwt(sharedIssuer, "alice");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(token)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA), "the token may belong to tenant B, so tenant A must not receive it without opting in");
            assertEquals(List.of(), tokensReceivedBy(providerB), "the token may belong to tenant A, so tenant B must not receive it without opting in");

            List<String> warnings = logEvents.list.stream()
                .filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
            assertEquals(2, warnings.size(), "each provider sharing the issuer is reported once: " + warnings);
            assertTrue(warnings.stream().anyMatch(w -> w.contains("[provider-a]") && w.contains("[provider-b]")), warnings.toString());
            assertTrue(warnings.stream().anyMatch(w -> w.contains("[provider-b]") && w.contains("[provider-a]")), warnings.toString());

            // the warning is logged once per validator, not once per request
            assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(token)));
            assertEquals(2, logEvents.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).count());
        } finally {
            factoryLogger.detachAppender(logEvents);
            logEvents.stop();
        }
    }

    @Test
    void jwtOfASharedIssuerIsForwardedOnlyToProvidersOptedIn() throws Exception {
        String sharedIssuer = "https://identity.example.org/";
        Map<String, Object> config = Map.of(
            "micronaut.security.oauth2.clients.provider-a.openid.issuer-identifier", sharedIssuer,
            "micronaut.security.oauth2.clients.provider-b.openid.issuer-identifier", sharedIssuer,
            "micronaut.security.oauth2.clients.provider-a.openid.user-info.validate-opaque-tokens", true,
            "micronaut.security.oauth2.clients.provider-b.openid.user-info.validate-opaque-tokens", false);
        try (EmbeddedServer server = startResourceServer(config)) {
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String token = signedJwt(sharedIssuer, "alice");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(token)));
            assertEquals("provider-a:alice", username);
            assertEquals(List.of(token), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB), "provider B did not opt in and must not receive tokens of the shared issuer");
        }
    }

    @Test
    void discoveryFailureOfOneProviderDoesNotMakeTheOtherTheSoleProvider() throws Exception {
        // Provider B is configured but its discovery document cannot be fetched, so only provider A gets a UserInfo validator.
        // That outage must not broaden which provider receives the tokens which cannot be attributed to a provider.
        providerB.getApplicationContext().getBean(FakeProvider.class).discoveryFails = true;
        try (EmbeddedServer server = startResourceServer(Map.of(), 1)) {
            List<UserInfoClientTokenValidator> validators = List.copyOf(server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class));
            assertEquals("provider-a", validators.get(0).getName());
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA), "provider A is not the sole configured provider, an opaque token which may belong to provider B must not reach it");
            assertEquals(List.of(), tokensReceivedBy(providerB));

            String noIssuer = signedJwt(null, "nobody");
            ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(noIssuer)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerA));

            // provider A still validates its own tokens
            String tokenForA = signedJwt(issuer(providerA), "alice");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(tokenForA)));
            assertEquals("provider-a:alice", username);
            assertEquals(List.of(tokenForA), tokensReceivedBy(providerA));
            assertEquals(List.of(), tokensReceivedBy(providerB));
        }
    }

    @Test
    void manuallyRegisteredProviderIsNotTheSoleProviderWhenTheConfiguredOneFailsDiscovery() throws Exception {
        // Provider A is configured under micronaut.security.oauth2.clients, provider B is registered as a configuration bean
        // sharing A's issuer. A's discovery fails, so B's validator is the only one, but two providers are trusted.
        providerA.getApplicationContext().getBean(FakeProvider.class).discoveryFails = true;
        UserInfoClientTokenValidatorConfiguration manualProviderB = UserInfoClientTokenValidatorConfiguration.builder()
            .name("manual-provider-b")
            .baseUrl(providerB.getURL().toString())
            .path("/userinfo")
            .issuer(issuer(providerA))
            .build();
        try (EmbeddedServer server = ApplicationContext.builder()
            .properties(Map.of(
                "spec.name", "UserInfoClientTokenValidatorMultipleProvidersTest",
                "micronaut.security.oauth2.clients.provider-a.client-id", "client-a",
                "micronaut.security.oauth2.clients.provider-a.client-secret", "test-fixture-not-a-secret",
                "micronaut.security.oauth2.clients.provider-a.openid.issuer", providerA.getURL().toString()))
            .singletons(manualProviderB)
            .start()
            .getBean(EmbeddedServer.class)) {
            server.start();
            List<UserInfoClientTokenValidator> validators = List.copyOf(server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class));
            assertEquals(1, validators.size());
            assertEquals("manual-provider-b", validators.get(0).getName());
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerB), "an opaque token which may belong to provider A must not reach provider B");

            String tokenForA = signedJwt(issuer(providerA), "alice");
            ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(tokenForA)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), tokensReceivedBy(providerB), "a JWT of the issuer shared with provider A must not reach provider B without opt-in");
            assertEquals(List.of(), tokensReceivedBy(providerA));
        }
    }

    private EmbeddedServer startResourceServer(Map<String, Object> extraConfig) {
        return startResourceServer(extraConfig, 2);
    }

    private EmbeddedServer startResourceServer(Map<String, Object> extraConfig, int expectedValidators) {
        Map<String, Object> config = new HashMap<>(Map.of(
            "spec.name", "UserInfoClientTokenValidatorMultipleProvidersTest",
            "micronaut.security.oauth2.clients.provider-a.client-id", "client-a",
            "micronaut.security.oauth2.clients.provider-a.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.provider-a.openid.issuer", providerA.getURL().toString(),
            "micronaut.security.oauth2.clients.provider-b.client-id", "client-b",
            "micronaut.security.oauth2.clients.provider-b.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.provider-b.openid.issuer", providerB.getURL().toString()
        ));
        config.putAll(extraConfig);
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config);
        assertEquals(expectedValidators, server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class).size());
        return server;
    }

    private static EmbeddedServer startProvider(String name) {
        EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "UserInfoClientTokenValidatorMultipleProvidersTestProvider"));
        FakeProvider fakeProvider = provider.getApplicationContext().getBean(FakeProvider.class);
        fakeProvider.name = name;
        fakeProvider.url = provider.getURL().toString();
        return provider;
    }

    private static String issuer(EmbeddedServer provider) {
        return provider.getApplicationContext().getBean(FakeProvider.class).issuer();
    }

    private static List<String> tokensReceivedBy(EmbeddedServer provider) {
        return provider.getApplicationContext().getBean(FakeProvider.class).receivedTokens;
    }

    private static HttpRequest<?> principalRequest(String token) {
        return HttpRequest.GET("/principal").bearerAuth(token).accept(MediaType.TEXT_PLAIN);
    }

    private static String signedJwt(String issuer, String subject) throws Exception {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().subject(subject);
        if (issuer != null) {
            claims.issuer(issuer);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims.build());
        jwt.sign(new MACSigner(NOT_A_SECRET));
        return jwt.serialize();
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorMultipleProvidersTest")
    @Controller("/principal")
    static class EchoUserController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorMultipleProvidersTestProvider")
    @Controller
    static class FakeProvider {
        private final List<String> receivedTokens = new CopyOnWriteArrayList<>();
        private String name;
        private String url;
        private String announcedIssuer;
        private boolean discoveryFails;

        String issuer() {
            return url + "/";
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> userinfo(@Header String authorization) {
            String token = authorization.substring("Bearer ".length());
            receivedTokens.add(token);
            String subject = token;
            try {
                subject = com.nimbusds.jwt.JWTParser.parse(token).getJWTClaimsSet().getSubject();
            } catch (java.text.ParseException ignored) {
                // opaque token
            }
            // the username is qualified with the provider name by the validator, which tells which provider answered
            return HttpResponse.ok(Map.of("sub", subject));
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        HttpResponse<String> discovery() {
            if (discoveryFails) {
                return HttpResponse.serverError();
            }
            return HttpResponse.ok("""
                {
                    "issuer":"%issuer",
                    "authorization_endpoint":"%s/authorize",
                    "token_endpoint":"%s/oauth/token",
                    "userinfo_endpoint":"%s/userinfo",
                    "jwks_uri":"%s/.well-known/jwks.json",
                    "response_types_supported":["code"],
                    "subject_types_supported":["public"],
                    "id_token_signing_alg_values_supported":["RS256"]
                }
                """.replace("%issuer", announcedIssuer != null ? announcedIssuer : issuer()).replace("%s", url));
        }
    }
}
