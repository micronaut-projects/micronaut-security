package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.core.beans.BeanIntrospection;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UserInfoClientTokenValidatorConfigurationTest {
    @Test
    void isAnnotatedWithIntrospected() {
        assertDoesNotThrow(() -> BeanIntrospection.getIntrospection(UserInfoClientTokenValidatorConfiguration.class));
    }

    @Test
    void defaultPathConstructor() {
        UserInfoClientTokenValidatorConfiguration config = new UserInfoClientTokenValidatorConfiguration("https://server.example.com", "example");
        assertEquals("https://server.example.com", config.baseUrl());
        assertEquals("example", config.name());
        assertEquals("example", config.getName());
        assertEquals("/userinfo", config.path());

        config = UserInfoClientTokenValidatorConfiguration.builder()
            .baseUrl("https://server.example.com")
            .name("example")
            .build();
        assertEquals("https://server.example.com", config.baseUrl());
        assertEquals("example", config.name());
        assertEquals("example", config.getName());
        assertEquals("/userinfo", config.path());
    }
    @Test
    void legacyConstructorsLeaveIssuerAndOpaqueTokenValidationUnset() {
        UserInfoClientTokenValidatorConfiguration config = new UserInfoClientTokenValidatorConfiguration("https://server.example.com", "example");
        assertNull(config.issuer());
        assertNull(config.validateOpaqueTokens());

        config = new UserInfoClientTokenValidatorConfiguration("https://server.example.com", "example", "/me");
        assertEquals("/me", config.path());
        assertNull(config.issuer());
        assertNull(config.validateOpaqueTokens());
    }

    @Test
    void builderSetsIssuerAndOpaqueTokenValidation() {
        UserInfoClientTokenValidatorConfiguration config = UserInfoClientTokenValidatorConfiguration.builder()
            .baseUrl("https://server.example.com")
            .name("example")
            .issuer("https://server.example.com/")
            .validateOpaqueTokens(true)
            .build();
        assertEquals("https://server.example.com/", config.issuer());
        assertEquals(Boolean.TRUE, config.validateOpaqueTokens());
        assertEquals("/userinfo", config.path());

        config = new UserInfoClientTokenValidatorConfiguration("https://server.example.com", "example", "/userinfo", "https://server.example.com/", false);
        assertEquals("https://server.example.com/", config.issuer());
        assertEquals(Boolean.FALSE, config.validateOpaqueTokens());
    }
}
