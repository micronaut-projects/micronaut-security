package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.core.beans.BeanIntrospection;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
}
