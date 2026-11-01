package io.micronaut.security.oauth2.endpoint.userinfo;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jwt.SignedJWT;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With a single OpenID provider, opaque tokens keep being validated against its UserInfo endpoint, but a JWT issued by
 * somebody else is never sent to it.
 */
class UserInfoClientTokenValidatorSingleProviderTest {
    private static final String OPAQUE_TOKEN = "opaque-test-fixture-not-a-secret";
    private static final byte[] NOT_A_SECRET = "test-fixture-not-a-secret-test-fixture-not-a-secret".getBytes(StandardCharsets.UTF_8);

    private EmbeddedServer provider;

    @BeforeEach
    void startProvider() {
        provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "UserInfoClientTokenValidatorSingleProviderTestProvider"));
        fakeProvider().url = provider.getURL().toString();
    }

    @AfterEach
    void stopProvider() {
        provider.close();
    }

    @Test
    void opaqueTokensAreValidatedByDefaultAndForeignJwtsAreNot() throws Exception {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            UserInfoClientTokenValidator validator = server.getApplicationContext().getBean(UserInfoClientTokenValidator.class);
            assertEquals("authserver", validator.getName());
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();

            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals(OPAQUE_TOKEN, username);
            assertEquals(List.of(OPAQUE_TOKEN), fakeProvider().receivedTokens);

            String ownJwt = signedJwt(fakeProvider().issuer(), "alice");
            username = assertDoesNotThrow(() -> client.retrieve(principalRequest(ownJwt)));
            assertEquals("alice", username);
            assertEquals(List.of(OPAQUE_TOKEN, ownJwt), fakeProvider().receivedTokens);

            String foreignJwt = signedJwt("https://idp.example.org/", "mallory");
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(foreignJwt)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(OPAQUE_TOKEN, ownJwt), fakeProvider().receivedTokens, "a JWT issued by another issuer must not be sent to the UserInfo endpoint");
        }
    }

    @Test
    void opaqueTokenValidationCanBeDisabled() {
        Map<String, Object> config = Map.of("micronaut.security.oauth2.clients.authserver.openid.user-info.validate-opaque-tokens", false);
        try (EmbeddedServer server = startResourceServer(config)) {
            UserInfoClientTokenValidatorConfiguration configuration = server.getApplicationContext().getBean(UserInfoClientTokenValidatorConfiguration.class);
            assertEquals(Boolean.FALSE, configuration.validateOpaqueTokens());
            assertEquals(provider.getURL().toString(), configuration.issuer(), "the configured issuer takes precedence over discovery");

            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(principalRequest(OPAQUE_TOKEN)));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
            assertEquals(List.of(), fakeProvider().receivedTokens);
        }
    }

    @Test
    void validateOpaqueTokensIsUnsetByDefault() {
        try (EmbeddedServer server = startResourceServer(Map.of())) {
            UserInfoClientTokenValidatorConfiguration configuration = server.getApplicationContext().getBean(UserInfoClientTokenValidatorConfiguration.class);
            assertNull(configuration.validateOpaqueTokens());
            assertEquals(provider.getURL().toString(), configuration.issuer(), "the configured issuer takes precedence over discovery");
        }
    }

    @Test
    void providerWithoutIssuerTreatsJwtsAsOpaqueTokensAndWarnsAtStartup() throws Exception {
        Logger factoryLogger = (Logger) LoggerFactory.getLogger(UserInfoClientFactory.class);
        ListAppender<ILoggingEvent> logEvents = new ListAppender<>();
        logEvents.start();
        factoryLogger.addAppender(logEvents);
        Map<String, Object> config = Map.of(
            "spec.name", "UserInfoClientTokenValidatorSingleProviderTest",
            "micronaut.security.oauth2.clients.authserver.client-id", "client",
            "micronaut.security.oauth2.clients.authserver.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.authserver.openid.fetch-configuration", false,
            "micronaut.security.oauth2.clients.authserver.openid.user-info.url", provider.getURL() + "/userinfo");
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config)) {
            UserInfoClientTokenValidatorConfiguration configuration = server.getApplicationContext().getBean(UserInfoClientTokenValidatorConfiguration.class);
            assertNull(configuration.issuer());
            List<String> warnings = logEvents.list.stream()
                .filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN))
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
            assertEquals(1, warnings.size(), "a UserInfo endpoint not bound to an issuer must be reported: " + warnings);
            assertTrue(warnings.get(0).contains("[authserver]"), warnings.get(0));

            // without an issuer the validator cannot attribute JWTs, so it falls back to the opaque token rule: sole provider, forwarded
            BlockingHttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
            String foreignJwt = signedJwt("https://idp.example.org/", "mallory");
            String username = assertDoesNotThrow(() -> client.retrieve(principalRequest(foreignJwt)));
            assertEquals("mallory", username);
            assertEquals(List.of(foreignJwt), fakeProvider().receivedTokens);
        } finally {
            factoryLogger.detachAppender(logEvents);
            logEvents.stop();
        }
    }

    private EmbeddedServer startResourceServer(Map<String, Object> extraConfig) {
        Map<String, Object> config = new HashMap<>(Map.of(
            "spec.name", "UserInfoClientTokenValidatorSingleProviderTest",
            "micronaut.security.oauth2.clients.authserver.client-id", "client",
            "micronaut.security.oauth2.clients.authserver.client-secret", "test-fixture-not-a-secret",
            "micronaut.security.oauth2.clients.authserver.openid.issuer", provider.getURL().toString()
        ));
        config.putAll(extraConfig);
        return ApplicationContext.run(EmbeddedServer.class, config);
    }

    private FakeProvider fakeProvider() {
        return provider.getApplicationContext().getBean(FakeProvider.class);
    }

    private static HttpRequest<?> principalRequest(String token) {
        return HttpRequest.GET("/principal").bearerAuth(token).accept(MediaType.TEXT_PLAIN);
    }

    private static String signedJwt(String issuer, String subject) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().issuer(issuer).subject(subject).build());
        jwt.sign(new MACSigner(NOT_A_SECRET));
        return jwt.serialize();
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorSingleProviderTest")
    @Controller("/principal")
    static class EchoUserController {
        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(Principal principal) {
            return principal.getName();
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorSingleProviderTestProvider")
    @Controller
    static class FakeProvider {
        private final List<String> receivedTokens = new CopyOnWriteArrayList<>();
        private String url;

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
            return HttpResponse.ok(Map.of("sub", subject));
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/.well-known/openid-configuration")
        String discovery() {
            return """
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
                """.replace("%issuer", issuer()).replace("%s", url);
        }
    }
}
