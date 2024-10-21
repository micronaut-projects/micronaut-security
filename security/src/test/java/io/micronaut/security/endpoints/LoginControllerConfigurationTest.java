package io.micronaut.security.endpoints;

import io.micronaut.http.MediaType;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@MicronautTest(startApplication = false)
class LoginControllerConfigurationTest {

    @Inject
    LoginControllerConfiguration loginControllerConfiguration;

    @Test
    void defaultContentType() {
        assertEquals(Set.of(MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON), loginControllerConfiguration.getPostContentTypes());
    }
}