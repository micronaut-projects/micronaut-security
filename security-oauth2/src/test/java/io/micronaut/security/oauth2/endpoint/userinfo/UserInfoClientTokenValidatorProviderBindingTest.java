package io.micronaut.security.oauth2.endpoint.userinfo;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.ProviderResolver;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.rules.SecurityRule;
import io.micronaut.security.token.Claims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The {@link Authentication} created from a UserInfo response must be bound to the provider which answered. Otherwise,
 * whoever controls one configured provider can return the subject of a victim at another configured provider and the
 * application sees the request as coming from the victim.
 */
class UserInfoClientTokenValidatorProviderBindingTest {
    private static final String QUALIFY_USERNAME_PROPERTY = OauthConfigurationProperties.OpenIdConfigurationProperties.PREFIX + ".qualify-username-with-provider";
    private static final String VICTIM_SUBJECT = "victim-subject-123";
    private static final String TOKEN_ISSUED_BY_A = "access-token-issued-by-provider-a-not-a-secret";
    private static final String TOKEN_ISSUED_BY_B = "access-token-issued-by-provider-b-not-a-secret";

    private EmbeddedServer providerA;
    private EmbeddedServer providerB;
    private Logger validatorLogger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> logEvents;

    @BeforeEach
    void startProviders() {
        providerA = startProvider(TOKEN_ISSUED_BY_A);
        providerB = startProvider(TOKEN_ISSUED_BY_B);
        validatorLogger = (Logger) LoggerFactory.getLogger(UserInfoClientTokenValidator.class);
        originalLevel = validatorLogger.getLevel();
        validatorLogger.setLevel(Level.WARN);
        logEvents = new ListAppender<>();
        logEvents.start();
        validatorLogger.addAppender(logEvents);
    }

    @AfterEach
    void stopProviders() {
        validatorLogger.detachAppender(logEvents);
        logEvents.stop();
        validatorLogger.setLevel(originalLevel);
        providerA.close();
        providerB.close();
    }

    @Test
    void providerCannotImpersonateUsersOfAnotherProvider() {
        // provider B is malicious: it returns the victim's subject at provider A and claims to be provider A
        fakeProvider(providerB).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            Claims.ISSUER, fakeProvider(providerA).issuer(),
            OauthAuthenticationMapper.PROVIDER_KEY, "provider-a");

        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            BlockingHttpClient client = client(server);

            Map<String, Object> victim = assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertEquals("provider-a:" + VICTIM_SUBJECT, victim.get("name"));
            assertEquals("provider-a", victim.get("provider"));
            assertEquals("provider-a", victim.get(OauthAuthenticationMapper.PROVIDER_KEY));
            assertEquals(VICTIM_SUBJECT, victim.get(Claims.SUBJECT));

            Map<String, Object> attacker = assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            assertNotEquals(victim.get("name"), attacker.get("name"), "a subject at provider B must never get the name of the same subject at provider A");
            assertEquals("provider-b:" + VICTIM_SUBJECT, attacker.get("name"));
            assertEquals("provider-b", attacker.get("provider"), "ProviderResolver must resolve the provider which answered, not the one claimed by the response");
            assertEquals("provider-b", attacker.get(OauthAuthenticationMapper.PROVIDER_KEY));
            assertEquals(VICTIM_SUBJECT, attacker.get(Claims.SUBJECT));
        }
    }

    @Test
    void responseClaimingAnotherProviderIsLoggedAtWarn() {
        fakeProvider(providerB).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            OauthAuthenticationMapper.PROVIDER_KEY, "provider-a");

        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            BlockingHttpClient client = client(server);

            assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertTrue(warnings().isEmpty(), "a response which does not claim a provider must not be reported: " + warnings());

            assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            List<ILoggingEvent> warnings = warnings();
            assertEquals(1, warnings.size(), "a response claiming another provider must be surfaced at WARN, not DEBUG: " + warnings);
            assertEquals("UserInfo response of client provider-b claimed to belong to provider provider-a. Ignoring it", warnings.get(0).getFormattedMessage());
            assertFalse(warnings.get(0).getFormattedMessage().contains(TOKEN_ISSUED_BY_B), "the token must not be logged");
        }
    }

    @Test
    void responseClaimingTheAnsweringProviderIsNotLogged() {
        fakeProvider(providerA).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            OauthAuthenticationMapper.PROVIDER_KEY, "provider-a");

        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertTrue(warnings().isEmpty(), "a response claiming the provider which answered is consistent and must not be reported: " + warnings());
        }
    }

    @Test
    void issuerClaimInUserInfoResponseDoesNotChangeTheResolvedProvider() {
        // no oauth2Provider in the response, only a forged iss which DefaultProviderResolver would otherwise fall back to
        fakeProvider(providerB).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            Claims.ISSUER, fakeProvider(providerA).issuer());

        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            Map<String, Object> attacker = assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            assertEquals("provider-b:" + VICTIM_SUBJECT, attacker.get("name"));
            assertEquals("provider-b", attacker.get("provider"));
            assertEquals("provider-b", attacker.get(OauthAuthenticationMapper.PROVIDER_KEY));
        }
    }

    @Test
    void tokensRejectedByEveryProviderAreNotAuthenticated() {
        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            BlockingHttpClient client = client(server);
            HttpClientResponseException ex = assertThrows(HttpClientResponseException.class,
                () -> client.retrieve(whoAmI("access-token-unknown-to-every-provider-not-a-secret"), MAP));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());

            fakeProvider(providerB).claims = Map.of("name", "no subject claim");
            ex = assertThrows(HttpClientResponseException.class, () -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatus());
        }
    }

    @Test
    void singleProviderKeepsTheSubjectAsNameButIsStillBoundToTheProvider() {
        fakeProvider(providerA).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            OauthAuthenticationMapper.PROVIDER_KEY, "somebody-else");

        try (EmbeddedServer server = startResourceServer(providerA)) {
            assertEquals(1, server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class).size());
            Map<String, Object> user = assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertEquals(VICTIM_SUBJECT, user.get("name"), "with a single provider the username is the subject, as before");
            assertEquals("provider-a", user.get("provider"));
            assertEquals("provider-a", user.get(OauthAuthenticationMapper.PROVIDER_KEY), "the provider attribute is never taken from the response");
        }
    }

    @Test
    void singleProviderQualifiesTheNameWhenTheOpenIdPropertyIsTrue() {
        try (EmbeddedServer server = startResourceServer(Map.of(QUALIFY_USERNAME_PROPERTY, true), providerA)) {
            Map<String, Object> user = assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertEquals("provider-a:" + VICTIM_SUBJECT, user.get("name"));
            assertEquals(VICTIM_SUBJECT, user.get(Claims.SUBJECT));
            assertEquals("provider-a", user.get(OauthAuthenticationMapper.PROVIDER_KEY));
        }
    }

    @Test
    void severalProvidersKeepTheSubjectAsNameWhenTheOpenIdPropertyIsFalseButStayBoundToTheAnsweringProvider() {
        fakeProvider(providerB).claims = Map.of(
            Claims.SUBJECT, VICTIM_SUBJECT,
            OauthAuthenticationMapper.PROVIDER_KEY, "provider-a");
        try (EmbeddedServer server = startResourceServer(Map.of(QUALIFY_USERNAME_PROPERTY, false), providerA, providerB)) {
            Map<String, Object> user = assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            assertEquals(VICTIM_SUBJECT, user.get("name"));
            assertEquals("provider-b", user.get("provider"));
            assertEquals("provider-b", user.get(OauthAuthenticationMapper.PROVIDER_KEY));
        }
    }

    @Test
    void subjectContainingTheSeparatorStaysUnambiguous() {
        // the provider name is guaranteed not to contain ':', so the provider is everything before the first ':'
        fakeProvider(providerB).claims = Map.of(Claims.SUBJECT, "provider-a:" + VICTIM_SUBJECT);
        fakeProvider(providerA).claims = Map.of(Claims.SUBJECT, VICTIM_SUBJECT);

        try (EmbeddedServer server = startResourceServer(providerA, providerB)) {
            BlockingHttpClient client = client(server);
            Map<String, Object> victim = assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            Map<String, Object> attacker = assertDoesNotThrow(() -> client.retrieve(whoAmI(TOKEN_ISSUED_BY_B), MAP));
            assertEquals("provider-a:" + VICTIM_SUBJECT, victim.get("name"));
            assertEquals("provider-b:provider-a:" + VICTIM_SUBJECT, attacker.get("name"));
            assertNotEquals(victim.get("name"), attacker.get("name"));
        }
    }

    @Test
    void providerNameContainingTheSeparatorIsRejectedWhenUsernamesAreQualified() {
        // provider "alpha:beta" with subject "victim" would otherwise get the same name as provider "alpha" with subject "beta:victim"
        ConfigurationException ex = assertThrows(ConfigurationException.class,
            () -> new UserInfoClientTokenValidator("alpha:beta", HttpClient.create(providerA.getURL()), "/userinfo", true));
        assertTrue(ex.getMessage().contains("'alpha:beta'"), ex.getMessage());
        assertTrue(ex.getMessage().contains(QUALIFY_USERNAME_PROPERTY), ex.getMessage());
    }

    @Test
    void providerNameContainingTheSeparatorIsAcceptedWhenUsernamesAreNotQualified() {
        try (UserInfoClientTokenValidator validator = assertDoesNotThrow(
            () -> new UserInfoClientTokenValidator("alpha:beta", HttpClient.create(providerA.getURL()), "/userinfo", false))) {
            assertEquals("alpha:beta", validator.getName());
        }
    }

    @Test
    void disabledClientsAreNotCountedWhenDecidingToQualifyTheName() {
        Map<String, Object> extra = Map.of("micronaut.security.oauth2.clients.provider-b.enabled", false);
        try (EmbeddedServer server = startResourceServer(extra, providerA, providerB)) {
            Map<String, Object> user = assertDoesNotThrow(() -> client(server).retrieve(whoAmI(TOKEN_ISSUED_BY_A), MAP));
            assertEquals(VICTIM_SUBJECT, user.get("name"));
        }
    }

    private static final Argument<Map<String, Object>> MAP = Argument.mapOf(String.class, Object.class);

    private List<ILoggingEvent> warnings() {
        return logEvents.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.WARN)).toList();
    }

    private static HttpRequest<?> whoAmI(String token) {
        return HttpRequest.GET("/whoami").bearerAuth(token);
    }

    private static BlockingHttpClient client(EmbeddedServer server) {
        return server.getApplicationContext().createBean(HttpClient.class, server.getURL()).toBlocking();
    }

    private static EmbeddedServer startResourceServer(EmbeddedServer... providers) {
        return startResourceServer(Map.of(), providers);
    }

    private static EmbeddedServer startResourceServer(Map<String, Object> extraConfig, EmbeddedServer... providers) {
        Map<String, Object> config = new HashMap<>(extraConfig);
        config.put("spec.name", "UserInfoClientTokenValidatorProviderBindingTest");
        String[] names = {"provider-a", "provider-b"};
        for (int i = 0; i < providers.length; i++) {
            String prefix = "micronaut.security.oauth2.clients." + names[i];
            config.put(prefix + ".client-id", "client-" + names[i]);
            config.put(prefix + ".client-secret", "test-fixture-not-a-secret");
            config.put(prefix + ".openid.issuer", providers[i].getURL().toString());
            // the tokens are opaque: every provider must opt in to receive tokens it cannot be attributed to, which is the
            // scenario of this test (a malicious provider answering for the tokens of another provider)
            config.put(prefix + ".openid.user-info.validate-opaque-tokens", true);
        }
        EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, config);
        if (extraConfig.isEmpty() || !extraConfig.containsKey("micronaut.security.oauth2.clients.provider-b.enabled")) {
            assertEquals(providers.length, server.getApplicationContext().getBeansOfType(UserInfoClientTokenValidator.class).size());
        }
        return server;
    }

    private static EmbeddedServer startProvider(String acceptedToken) {
        EmbeddedServer provider = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "UserInfoClientTokenValidatorProviderBindingTestProvider"));
        FakeProvider fakeProvider = fakeProvider(provider);
        fakeProvider.url = provider.getURL().toString();
        fakeProvider.acceptedToken = acceptedToken;
        fakeProvider.claims = Map.of(Claims.SUBJECT, VICTIM_SUBJECT);
        return provider;
    }

    private static FakeProvider fakeProvider(EmbeddedServer provider) {
        return provider.getApplicationContext().getBean(FakeProvider.class);
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorProviderBindingTest")
    @Controller("/whoami")
    static class WhoAmIController {
        private final ProviderResolver providerResolver;

        WhoAmIController(ProviderResolver providerResolver) {
            this.providerResolver = providerResolver;
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Get
        Map<String, Object> index(Authentication authentication) {
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("name", authentication.getName());
            result.put("provider", providerResolver.resolveProvider(authentication).orElse(null));
            result.put(OauthAuthenticationMapper.PROVIDER_KEY, authentication.getAttributes().get(OauthAuthenticationMapper.PROVIDER_KEY));
            result.put(Claims.SUBJECT, authentication.getAttributes().get(Claims.SUBJECT));
            return result;
        }
    }

    @Requires(property = "spec.name", value = "UserInfoClientTokenValidatorProviderBindingTestProvider")
    @Controller
    static class FakeProvider {
        private volatile String url;
        private volatile String acceptedToken;
        private volatile Map<String, Object> claims;

        String issuer() {
            return url + "/";
        }

        @Secured(SecurityRule.IS_ANONYMOUS)
        @Get("/userinfo")
        HttpResponse<?> userinfo(@Header String authorization) {
            if (authorization.equals("Bearer " + acceptedToken)) {
                return HttpResponse.ok(claims);
            }
            return HttpResponse.unauthorized();
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
