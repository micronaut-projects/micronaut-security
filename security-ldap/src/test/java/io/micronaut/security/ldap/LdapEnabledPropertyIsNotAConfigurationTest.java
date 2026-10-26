package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code micronaut.security.ldap.enabled} is the documented global switch for LDAP authentication. It must not be
 * bound as an {@link LdapConfiguration} named {@code enabled} that has no server, because the authentication
 * provider created for such a configuration throws instead of rejecting the credentials, and the resulting
 * 500 responses let an anonymous client tell unknown usernames (500) apart from wrong passwords (401).
 */
class LdapEnabledPropertyIsNotAConfigurationTest {

    private static final String SPEC_NAME = "LdapEnabledPropertyIsNotAConfigurationTest";
    private static final String MANAGER_DN = "cn=admin,dc=example,dc=com";
    private static final String EXISTING_USER = "euclid";
    private static final String UNKNOWN_USER = "nobody-in-this-directory";
    private static final int ATTEMPTS = 25;

    private static InMemoryDirectoryServer server;

    @BeforeAll
    static void startDirectory() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials(MANAGER_DN, "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapEnabledPropertyIsNotAConfigurationTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
    }

    @AfterAll
    static void stopDirectory() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void globalEnabledSwitchDoesNotCreateAnLdapConfiguration() {
        Map<String, Object> properties = defaultConfiguration();
        properties.put("micronaut.security.ldap.enabled", true);

        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            List<String> names = context.getBeansOfType(LdapConfiguration.class).stream().map(LdapConfiguration::getName).collect(Collectors.toList());
            assertEquals(Collections.singletonList("default"), names);
            assertFalse(context.findBean(LdapConfiguration.class, Qualifiers.byName("enabled")).isPresent());
            assertEquals(1, context.getBeansOfType(LdapAuthenticationProvider.class).size());
            assertTrue(context.findBean(LdapAuthenticationProvider.class, Qualifiers.byName("default")).isPresent());
            assertFalse(context.findBean(LdapAuthenticationProvider.class, Qualifiers.byName("enabled")).isPresent());
        }
    }

    @Test
    void leafKeyUnderTheLdapPrefixDoesNotCreateAnLdapConfiguration() {
        Map<String, Object> properties = defaultConfiguration();
        properties.put("micronaut.security.ldap.timeout", "5s");

        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            List<String> names = context.getBeansOfType(LdapConfiguration.class).stream().map(LdapConfiguration::getName).collect(Collectors.toList());
            assertEquals(Collections.singletonList("default"), names);
            assertEquals(1, context.getBeansOfType(LdapAuthenticationProvider.class).size());
        }
    }

    @Test
    void globalEnabledSwitchSetToFalseDisablesEveryLdapProvider() {
        Map<String, Object> properties = defaultConfiguration();
        properties.put("micronaut.security.ldap.enabled", false);
        properties.put("micronaut.security.ldap.default.enabled", true);

        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            assertTrue(context.getBeansOfType(LdapAuthenticationProvider.class).isEmpty());
        }
    }

    @Test
    void unknownUsernameIsRejectedWithUnauthorizedNotServerError() {
        Map<String, Object> properties = defaultConfiguration();
        properties.put("micronaut.security.ldap.enabled", true);

        try (EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer.class, properties, "test");
             HttpClient httpClient = embeddedServer.getApplicationContext().createBean(HttpClient.class, embeddedServer.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            for (int i = 0; i < ATTEMPTS; i++) {
                assertEquals(HttpStatus.UNAUTHORIZED, statusOf(client, UNKNOWN_USER, "password"), "attempt " + i + " for an unknown username");
                assertEquals(HttpStatus.UNAUTHORIZED, statusOf(client, EXISTING_USER, "wrong-password"), "attempt " + i + " for a wrong password");
            }

            HttpResponse<String> ok = client.exchange(HttpRequest.GET("/whoami").basicAuth(EXISTING_USER, "password"), String.class);
            assertEquals(HttpStatus.OK, ok.getStatus());
            assertEquals(EXISTING_USER, ok.getBody().orElse(""));
        }
    }

    private static HttpStatus statusOf(BlockingHttpClient client, String username, String password) {
        HttpRequest<?> request = HttpRequest.GET("/whoami").basicAuth(username, password);
        HttpClientResponseException e = assertThrows(HttpClientResponseException.class, () -> client.exchange(request, String.class));
        return e.getStatus();
    }

    private static Map<String, Object> defaultConfiguration() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort());
        properties.put("micronaut.security.ldap.default.context.managerDn", MANAGER_DN);
        properties.put("micronaut.security.ldap.default.context.managerPassword", "password");
        properties.put("micronaut.security.ldap.default.search.base", "dc=example,dc=com");
        return properties;
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/whoami")
    static class WhoAmIController {

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String whoami(Principal principal) {
            return principal.getName();
        }
    }
}
