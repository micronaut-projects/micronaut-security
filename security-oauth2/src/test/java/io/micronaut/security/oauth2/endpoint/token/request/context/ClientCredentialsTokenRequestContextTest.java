package io.micronaut.security.oauth2.endpoint.token.request.context;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.grants.SecureGrant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientCredentialsTokenRequestContextTest {

    private final Logger logger = (Logger) LoggerFactory.getLogger(ClientCredentialsTokenRequestContext.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void setUp() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void additionalRequestParamsCannotOverrideReservedKeys() {
        OauthClientConfiguration configuration = configuration("reserved-keys-client", null,
            Map.of("grant_type", "password", "client_secret", "x", "client_id", "evil", "audience", "api"));

        Map<String, String> grant = new ClientCredentialsTokenRequestContext(configuration).getGrant();

        assertEquals(Map.of("grant_type", "client_credentials", "audience", "api"), grant);
    }

    @Test
    void configuredClientSecretIsUsedWhenSecuredWithClientSecretPost() {
        OauthClientConfiguration configuration = configuration("client-secret-post-client", null,
            Map.of("grant_type", "password", "client_secret", "x", "audience", "api"));

        Map<String, String> grant = new ClientCredentialsTokenRequestContext(configuration).getGrant();
        // DefaultTokenEndpointClient does this for client_secret_post
        ((SecureGrant) grant).setClientId(configuration.getClientId());
        ((SecureGrant) grant).setClientSecret(configuration.getClientSecret());

        assertEquals(Map.of(
            "grant_type", "client_credentials",
            "client_id", "client-id",
            "client_secret", "configured-secret",
            "audience", "api"), grant);
    }

    @Test
    void additionalRequestParamsCannotOverrideRequestedScope() {
        OauthClientConfiguration configuration = configuration("scope-client", "read",
            Map.of("scope", "admin", "audience", "api"));

        Map<String, String> grant = new ClientCredentialsTokenRequestContext("read", configuration).getGrant();

        assertEquals(Map.of("grant_type", "client_credentials", "scope", "read", "audience", "api"), grant);
    }

    @Test
    void additionalScopeIsUsedWhenNoScopeIsRequested() {
        OauthClientConfiguration configuration = configuration("no-scope-client", null,
            Map.of("scope", "admin"));

        Map<String, String> grant = new ClientCredentialsTokenRequestContext(null, configuration).getGrant();

        assertEquals("admin", grant.get("scope"));
    }

    @Test
    void ignoredKeyWarningIsLoggedOncePerClient() {
        OauthClientConfiguration configuration = configuration("warn-once-client", null,
            Map.of("grant_type", "password", "audience", "api"));

        new ClientCredentialsTokenRequestContext(configuration).getGrant();
        new ClientCredentialsTokenRequestContext(configuration).getGrant();
        ClientCredentialsTokenRequestContext context = new ClientCredentialsTokenRequestContext(configuration);
        context.getGrant();
        context.getGrant();

        List<ILoggingEvent> warnings = appender.list.stream()
            .filter(event -> event.getLevel() == Level.WARN)
            .filter(event -> event.getFormattedMessage().contains("warn-once-client"))
            .toList();
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).getFormattedMessage().contains("[grant_type]"));
    }

    private static OauthClientConfiguration configuration(String name, String scope, Map<String, String> additionalRequestParams) {
        return OauthClientConfiguration.builder()
            .name(name)
            .clientId("client-id")
            .clientSecret("configured-secret")
            .token("https://auth.example.com/token")
            .clientCredentials(scope, Duration.ofSeconds(30), additionalRequestParams)
            .build();
    }
}
