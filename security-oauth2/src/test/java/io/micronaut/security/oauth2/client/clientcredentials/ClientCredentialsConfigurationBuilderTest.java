package io.micronaut.security.oauth2.client.clientcredentials;

import io.micronaut.security.oauth2.client.clientcredentials.propagation.ClientCredentialsHeaderTokenPropagatorConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class ClientCredentialsConfigurationBuilderTest {

    @Test
    void ofCreatesClientCredentialsConfigurationBuilder() {
        ClientCredentialsConfigurationBuilder builder = ClientCredentialsConfiguration.builder();

        assertNotNull(builder);
        assertNotSame(builder, ClientCredentialsConfiguration.builder());
    }

    @Test
    void buildsDefaultConfiguration() {
        ClientCredentialsConfiguration configuration = ClientCredentialsConfiguration.builder().build();

        assertTrue(configuration.isEnabled());
        assertFalse(configuration.getScope().isPresent());
        assertEquals(OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION, configuration.getAdvancedExpiration());
        assertFalse(configuration.getHeaderPropagation().isPresent());
        assertEquals(Map.of(), configuration.getAdditionalRequestParams());
        assertNull(configuration.getServiceIdPattern());
        assertNull(configuration.getUriPattern());
    }

    @Test
    void buildsConfiguredConfiguration() {
        Map<String, String> additionalRequestParams = new HashMap<>(Map.of("audience", "https://api.example.com"));
        Duration advancedExpiration = Duration.ofMinutes(2);
        ClientCredentialsHeaderTokenPropagatorConfiguration headerPropagation = mock(ClientCredentialsHeaderTokenPropagatorConfiguration.class);

        ClientCredentialsConfiguration configuration = ClientCredentialsConfiguration.builder()
                .enabled(false)
                .scope("read write")
                .advancedExpiration(advancedExpiration)
                .headerPropagation(headerPropagation)
                .additionalRequestParams(additionalRequestParams)
                .serviceIdRegex("inventory|billing")
                .uriRegex("/api/.*")
                .build();
        additionalRequestParams.put("resource", "https://resource.example.com");

        assertFalse(configuration.isEnabled());
        assertEquals("read write", configuration.getScope().orElseThrow());
        assertEquals(advancedExpiration, configuration.getAdvancedExpiration());
        assertSame(headerPropagation, configuration.getHeaderPropagation().orElseThrow());
        assertEquals(Map.of("audience", "https://api.example.com"), configuration.getAdditionalRequestParams());
        assertThrows(UnsupportedOperationException.class, () -> configuration.getAdditionalRequestParams().put("resource", "https://resource.example.com"));
        assertEquals("inventory|billing", configuration.getServiceIdPattern().pattern());
        assertTrue(configuration.getServiceIdPattern().matcher("inventory").matches());
        assertEquals("/api/.*", configuration.getUriPattern().pattern());
        assertTrue(configuration.getUriPattern().matcher("/api/orders").matches());
    }

    @Test
    void rejectsNullRequiredValues() {
        NullPointerException missingAdvancedExpiration = assertThrows(NullPointerException.class, () ->
                ClientCredentialsConfiguration.builder().advancedExpiration(null)
        );
        assertEquals("advancedExpiration", missingAdvancedExpiration.getMessage());

        NullPointerException missingAdditionalRequestParams = assertThrows(NullPointerException.class, () ->
                ClientCredentialsConfiguration.builder().additionalRequestParams(null)
        );
        assertEquals("additionalRequestParams", missingAdditionalRequestParams.getMessage());
    }
}
