package io.micronaut.security.oauth2.endpoint.token.request.context;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.token.request.DefaultTokenEndpointClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
    void clientSecretPostSendsTheConfiguredCredentialsInTheBody() {
        OauthClientConfiguration configuration = configuration("client-secret-post-client", null,
            AuthenticationMethods.CLIENT_SECRET_POST,
            Map.of("grant_type", "password", "client_secret", "x", "client_id", "evil", "audience", "api"));

        MutableHttpRequest<Map<String, String>> request = new SecuringTokenEndpointClient()
            .secured(new ClientCredentialsTokenRequestContext(configuration));

        assertEquals(Map.of(
            "grant_type", "client_credentials",
            "client_id", "client-id",
            "client_secret", "configured-secret",
            "audience", "api"), request.getBody().orElseThrow());
        assertFalse(request.getHeaders().contains(HttpHeaders.AUTHORIZATION));
    }

    @Test
    void clientSecretBasicKeepsCredentialsOutOfTheBody() {
        OauthClientConfiguration configuration = configuration("client-secret-basic-client", null,
            AuthenticationMethods.CLIENT_SECRET_BASIC,
            Map.of("client_secret", "x", "client_id", "evil", "audience", "api"));

        MutableHttpRequest<Map<String, String>> request = new SecuringTokenEndpointClient()
            .secured(new ClientCredentialsTokenRequestContext(configuration));

        assertEquals(Map.of("grant_type", "client_credentials", "audience", "api"), request.getBody().orElseThrow());
        String credentials = Base64.getEncoder().encodeToString("client-id:configured-secret".getBytes(StandardCharsets.UTF_8));
        assertEquals("Basic " + credentials, request.getHeaders().get(HttpHeaders.AUTHORIZATION));
    }

    @Test
    void additionalRequestParamsCannotOverrideScopeRequestedWithAnExplicitEndpoint() {
        OauthClientConfiguration configuration = configuration("explicit-endpoint-client", "read",
            Map.of("scope", "admin", "audience", "api"));

        Map<String, String> grant = new ClientCredentialsTokenRequestContext("read", configuration.getTokenEndpoint(), configuration).getGrant();

        assertEquals(Map.of("grant_type", "client_credentials", "scope", "read", "audience", "api"), grant);
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
        String clientName = uniqueClientName("warn-once-client");
        OauthClientConfiguration configuration = configuration(clientName, null,
            Map.of("grant_type", "password", "audience", "api"));

        new ClientCredentialsTokenRequestContext(configuration).getGrant();
        new ClientCredentialsTokenRequestContext(configuration).getGrant();
        ClientCredentialsTokenRequestContext context = new ClientCredentialsTokenRequestContext(configuration);
        context.getGrant();
        context.getGrant();

        List<String> warnings = warnings(clientName);
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("[grant_type]"));
    }

    @Test
    void ignoredKeyWarningNamesTheReasonAndNeverTheValue() {
        String clientName = uniqueClientName("warn-reason-client");
        OauthClientConfiguration configuration = configuration(clientName, "read",
            Map.of("client_secret", "leaked-secret", "scope", "leaked-scope"));

        new ClientCredentialsTokenRequestContext("read", configuration).getGrant();

        List<String> warnings = warnings(clientName);
        assertEquals(2, warnings.size());
        assertTrue(warnings.stream().anyMatch(message -> message.contains("[client_secret]") && message.contains("reserved")));
        assertTrue(warnings.stream().anyMatch(message -> message.contains("[scope]") && message.contains("already sets it")));
        assertTrue(warnings.stream().noneMatch(message -> message.contains("leaked")));
    }

    /**
     * Warnings are logged once per client name for the lifetime of the JVM, so a rerun in the same JVM needs a new name.
     */
    private static String uniqueClientName(String prefix) {
        return prefix + '-' + UUID.randomUUID();
    }

    private List<String> warnings(String clientName) {
        return appender.list.stream()
            .filter(event -> event.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .filter(message -> message.contains(clientName))
            .toList();
    }

    private static OauthClientConfiguration configuration(String name, String scope, Map<String, String> additionalRequestParams) {
        return configuration(name, scope, null, additionalRequestParams);
    }

    private static OauthClientConfiguration configuration(String name, String scope, String authenticationMethod, Map<String, String> additionalRequestParams) {
        return OauthClientConfiguration.builder()
            .name(name)
            .clientId("client-id")
            .clientSecret("configured-secret")
            .token("https://auth.example.com/token", authenticationMethod)
            .clientCredentials(scope, Duration.ofSeconds(30), additionalRequestParams)
            .build();
    }

    /**
     * Exposes how {@link DefaultTokenEndpointClient} secures a client credentials request, without sending it.
     */
    private static final class SecuringTokenEndpointClient extends DefaultTokenEndpointClient {

        SecuringTokenEndpointClient() {
            super(null, () -> null);
        }

        MutableHttpRequest<Map<String, String>> secured(ClientCredentialsTokenRequestContext context) {
            MutableHttpRequest<Map<String, String>> request = HttpRequest.POST(context.getEndpoint().getUrl(), context.getGrant());
            secureRequest(request, context);
            return request;
        }
    }
}
