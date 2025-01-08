package io.micronaut.security.csrf;

import io.micronaut.http.cookie.SameSite;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.temporal.TemporalAmount;
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
    void defaultRandomValueSize() {
        assertEquals(16, csrfConfiguration.getRandomValueSize());
    }

    @Test
    void defaultCookiePath() {
        assertTrue(csrfConfiguration.getCookiePath().isPresent());
        assertEquals("/", csrfConfiguration.getCookiePath().get());
    }

    @Test
    void defaultCookieName() {
        assertEquals("__Host-csrfToken", csrfConfiguration.getCookieName());
    }

    @Test
    void defaultSameSite() {
        assertTrue(csrfConfiguration.getCookieSameSite().isPresent());
        assertEquals(SameSite.Strict, csrfConfiguration.getCookieSameSite().get());
    }

    @Test
    void defaultCookieSecure() {
        assertTrue(csrfConfiguration.isCookieSecure().isPresent());
        assertEquals(Boolean.TRUE, csrfConfiguration.isCookieSecure().get());
    }

    @Test
    void defaultCookieHttpOnly() {
        assertTrue(csrfConfiguration.isCookieHttpOnly().isPresent());
        assertEquals(Boolean.TRUE, csrfConfiguration.isCookieHttpOnly().get());
    }

    @Test
    void defaultCookieDomain() {
        assertTrue(csrfConfiguration.getCookieDomain().isEmpty());
    }

    @Test
    void defaultCookieMaxAge() {
        assertTrue(csrfConfiguration.getCookieMaxAge().isPresent());
        TemporalAmount expected = Duration.ofSeconds(3600);
        assertEquals(expected, csrfConfiguration.getCookieMaxAge().get());
    }

    @Test
    void defaultSecretKey() {
        assertNull(csrfConfiguration.getSecretKey());
    }
}