package io.micronaut.security.csrf;

import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest(startApplication = false)
class CsrfConfigurationTest {

    @Inject
    CsrfConfiguration csrfConfiguration;

    @Test
    void defaultHeaderName() {
        assertEquals("X-CSRF-TOKEN", csrfConfiguration.getHeaderName());
    }

    @Test
    void defaultFieldName() {
        assertEquals("csrfToken", csrfConfiguration.getFieldName());
    }

    @Test
    void defaultEnabled() {
        assertTrue(csrfConfiguration.isEnabled());
    }

    @Test
    void defaultHttpSessionName() {
        assertEquals("csrfToken", csrfConfiguration.getHttpSessionName());
    }

    @Test
    void defaultTokenSize() {
        assertEquals(16, csrfConfiguration.getTokenSize());
    }
}