package io.micronaut.security.oauth2.configuration.endpoints;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecureEndpointConfigurationBuilderTest {

    @Test
    void builderCreatesSecureEndpointConfigurationBuilder() {
        SecureEndpointConfigurationBuilder builder = SecureEndpointConfiguration.builder();

        assertNotNull(builder);
        assertNotSame(builder, SecureEndpointConfiguration.builder());
    }

    @Test
    void builderMethodsReturnSameBuilder() {
        SecureEndpointConfigurationBuilder builder = SecureEndpointConfiguration.builder();

        assertSame(builder, builder.url("https://auth.example.com/introspect"));
        assertSame(builder, builder.authenticationMethod("client_secret_post"));
    }

    @Test
    void buildsDefaultConfiguration() {
        SecureEndpointConfiguration configuration = SecureEndpointConfiguration.builder().build();

        assertFalse(configuration.getUrl().isPresent());
        assertFalse(configuration.getAuthenticationMethod().isPresent());
    }

    @Test
    void buildsConfiguredConfiguration() {
        SecureEndpointConfiguration configuration = SecureEndpointConfiguration.builder()
                .url("https://auth.example.com/introspect")
                .authenticationMethod("client_secret_post")
                .build();

        assertEquals("https://auth.example.com/introspect", configuration.getUrl().orElseThrow());
        assertEquals("client_secret_post", configuration.getAuthenticationMethod().orElseThrow());
    }

    @Test
    void rejectsNullRequiredValues() {
        NullPointerException missingUrl = assertThrows(NullPointerException.class, () ->
                SecureEndpointConfiguration.builder().url(null)
        );
        assertEquals("url", missingUrl.getMessage());
    }
}
