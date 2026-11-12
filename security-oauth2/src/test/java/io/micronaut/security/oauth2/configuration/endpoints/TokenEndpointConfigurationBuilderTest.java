package io.micronaut.security.oauth2.configuration.endpoints;

import io.micronaut.http.MediaType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenEndpointConfigurationBuilderTest {

    @Test
    void builderCreatesTokenEndpointConfigurationBuilder() {
        TokenEndpointConfigurationBuilder builder = TokenEndpointConfiguration.builder();

        assertNotNull(builder);
        assertNotSame(builder, TokenEndpointConfiguration.builder());
    }

    @Test
    void builderMethodsReturnSameBuilder() {
        TokenEndpointConfigurationBuilder builder = TokenEndpointConfiguration.builder();

        assertSame(builder, builder.url("https://auth.example.com/token"));
        assertSame(builder, builder.authenticationMethod("client_secret_post"));
        assertSame(builder, builder.contentType(MediaType.APPLICATION_JSON_TYPE));
    }

    @Test
    void buildsDefaultConfiguration() {
        TokenEndpointConfiguration configuration = TokenEndpointConfiguration.builder().build();

        assertFalse(configuration.getUrl().isPresent());
        assertFalse(configuration.getAuthenticationMethod().isPresent());
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED_TYPE, configuration.getContentType());
    }

    @Test
    void buildsConfiguredConfiguration() {
        TokenEndpointConfiguration configuration = TokenEndpointConfiguration.builder()
                .url("https://auth.example.com/token")
                .authenticationMethod("client_secret_post")
                .contentType(MediaType.APPLICATION_JSON_TYPE)
                .build();

        assertEquals("https://auth.example.com/token", configuration.getUrl().orElseThrow());
        assertEquals("client_secret_post", configuration.getAuthenticationMethod().orElseThrow());
        assertEquals(MediaType.APPLICATION_JSON_TYPE, configuration.getContentType());
    }

    @Test
    void rejectsNullRequiredValues() {
        NullPointerException missingUrl = assertThrows(NullPointerException.class, () ->
                TokenEndpointConfiguration.builder().url(null)
        );
        assertEquals("url", missingUrl.getMessage());

        NullPointerException missingContentType = assertThrows(NullPointerException.class, () ->
                TokenEndpointConfiguration.builder().contentType(null)
        );
        assertEquals("contentType", missingContentType.getMessage());
    }
}
