package io.micronaut.security.csrf;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@Property(name = "micronaut.security.csrf.header-name", value = "header-foo")
@Property(name = "micronaut.security.csrf.field-name", value = "field-foo")
@Property(name = "micronaut.security.csrf.random-value-size", value = "5")
@Property(name = "micronaut.security.csrf.http-session-name", value = "session-foo")
@Property(name = "micronaut.security.csrf.cookie-domain", value = "cookie-domain-foo")
@Property(name = "micronaut.security.csrf.cookie-secure", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.cookie-path", value = "cookie-path-foo")
@Property(name = "micronaut.security.csrf.cookie-http-only", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csrf.cookie-max-age", value = "5s")
@Property(name = "micronaut.security.csrf.cookie-name", value = "cookie-name-foo")
@Property(name = "micronaut.security.csrf.cookie-same-site", value = "Lax")
@Property(name = "micronaut.security.csrf.signature-key", value = "signature-key-foo")
@MicronautTest(startApplication = false)
class CsrfConfigurationPropertiesTest {
    @Test
    void settingCsrfConfiguration(CsrfConfiguration csrfConfiguration) {
        assertEquals("header-foo", csrfConfiguration.getHeaderName());
        assertEquals("field-foo", csrfConfiguration.getFieldName());
        assertEquals(5, csrfConfiguration.getRandomValueSize());
        assertEquals("session-foo" ,csrfConfiguration.getHttpSessionName());
        assertTrue(csrfConfiguration.getCookieDomain().isPresent());
        assertEquals("cookie-domain-foo", csrfConfiguration.getCookieDomain().get());
        assertTrue(csrfConfiguration.isCookieSecure().isPresent());
        assertFalse(csrfConfiguration.isCookieSecure().get());
        assertTrue(csrfConfiguration.getCookiePath().isPresent());
        assertEquals("cookie-path-foo", csrfConfiguration.getCookiePath().get());
        assertTrue(csrfConfiguration.isCookieHttpOnly().isPresent());
        assertFalse(csrfConfiguration.isCookieHttpOnly().get());
        assertTrue(csrfConfiguration.getCookieMaxAge().isPresent());
        assertEquals(Duration.ofSeconds(5), csrfConfiguration.getCookieMaxAge().get());
        assertEquals("cookie-name-foo", csrfConfiguration.getCookieName());
        assertTrue(csrfConfiguration.getCookieSameSite().isPresent());
        assertEquals(SameSite.Lax, csrfConfiguration.getCookieSameSite().get());
        assertEquals("signature-key-foo", csrfConfiguration.getSecretKey());
    }
}
