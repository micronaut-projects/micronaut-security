package io.micronaut.security.endpoints;

import io.micronaut.http.MediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(startApplication = false)
class LogoutControllerConfigurationTest {

    @Inject
    LogoutControllerConfiguration logoutControllerConfiguration;

    @Test
    void defaultContentType() {
        assertEquals(Set.of(MediaType.APPLICATION_FORM_URLENCODED_TYPE, MediaType.APPLICATION_JSON_TYPE), logoutControllerConfiguration.getPostContentTypes());
    }
}