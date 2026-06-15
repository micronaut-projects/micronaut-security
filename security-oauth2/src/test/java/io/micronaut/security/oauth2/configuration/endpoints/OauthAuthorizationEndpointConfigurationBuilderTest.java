package io.micronaut.security.oauth2.configuration.endpoints;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OauthAuthorizationEndpointConfigurationBuilderTest {

    @Test
    void builderCreatesOauthAuthorizationEndpointConfigurationBuilder() {
        OauthAuthorizationEndpointConfigurationBuilder builder = OauthAuthorizationEndpointConfiguration.builder();

        assertNotNull(builder);
        assertNotSame(builder, OauthAuthorizationEndpointConfiguration.builder());
    }

    @Test
    void builderMethodsReturnSameBuilder() {
        OauthAuthorizationEndpointConfigurationBuilder builder = OauthAuthorizationEndpointConfiguration.builder();

        assertSame(builder, builder.url("https://auth.example.com/authorize"));
        assertSame(builder, builder.codeChallengeMethod("S256"));
    }

    @Test
    void buildsDefaultConfiguration() {
        OauthAuthorizationEndpointConfiguration configuration = OauthAuthorizationEndpointConfiguration.builder().build();

        assertFalse(configuration.getUrl().isPresent());
        assertFalse(configuration.getCodeChallengeMethod().isPresent());
    }

    @Test
    void buildsConfiguredConfiguration() {
        OauthAuthorizationEndpointConfiguration configuration = OauthAuthorizationEndpointConfiguration.builder()
                .url("https://auth.example.com/authorize")
                .codeChallengeMethod("S256")
                .build();

        assertEquals("https://auth.example.com/authorize", configuration.getUrl().orElseThrow());
        assertEquals("S256", configuration.getCodeChallengeMethod().orElseThrow());
    }

    @Test
    void rejectsNullRequiredValues() {
        NullPointerException missingUrl = assertThrows(NullPointerException.class, () ->
                OauthAuthorizationEndpointConfiguration.builder().url(null)
        );
        assertEquals("url", missingUrl.getMessage());
    }
}
