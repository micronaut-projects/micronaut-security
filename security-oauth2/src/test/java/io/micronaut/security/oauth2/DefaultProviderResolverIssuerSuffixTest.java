package io.micronaut.security.oauth2;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A token {@code iss} that is only a suffix of an OpenID client issuer must not resolve that client as the token's provider.
 */
class DefaultProviderResolverIssuerSuffixTest {

    private static final String CONFIGURED_ISSUER = "https://auth.example.com/realms/master";

    private static ApplicationContext context;
    private static DefaultProviderResolver resolver;

    @BeforeAll
    static void setup() {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.oauth2.clients.keycloak.client-id", "test-client-id");
        configuration.put("micronaut.security.oauth2.clients.keycloak.client-secret", "test-fixture-not-a-secret");
        // discovery is fetched at startup on this branch: a closed port fails fast; the resolver compares the issuer identifier
        configuration.put("micronaut.security.oauth2.clients.keycloak.openid.issuer", "http://localhost:1/realms/master");
        configuration.put("micronaut.security.oauth2.clients.keycloak.openid.issuer-identifier", CONFIGURED_ISSUER);
        context = ApplicationContext.run(configuration);
        OpenIdClientConfiguration openId = context.getBean(OauthClientConfiguration.class).getOpenid().get();
        resolver = new DefaultProviderResolver(Collections.singletonList(openId));
    }

    @AfterAll
    static void cleanup() {
        context.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"master", "realms/master", "/realms/master", "https://auth.example.com", "example.com", "com", "", "https://", "/",
            "auth.example.com/realms/master", "http://auth.example.com/realms/master", "https://Auth.example.com/realms/master",
            "https://auth.example.com:443/realms/master", "https://evil.com@auth.example.com/realms/master", "https://auth.example.com/realms/master//"})
    void suffixOfTheConfiguredIssuerDoesNotResolveTheProvider(String iss) {
        Optional<String> name = resolver.openIdClientNameWhichMatchesIssuer(iss);
        assertFalse(name.isPresent(), () -> "iss '" + iss + "' must not resolve to a provider");
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://auth.example.com/realms/master", "https://auth.example.com/realms/master/", "HTTPS://auth.example.com/realms/master"})
    void exactIssuerResolvesTheProvider(String iss) {
        Optional<String> name = resolver.openIdClientNameWhichMatchesIssuer(iss);
        assertTrue(name.isPresent());
        assertEquals("keycloak", name.get());
    }
}
