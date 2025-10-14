package io.micronaut.security.csrf;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Property(name = "micronaut.security.csrf.session-cookie", value = StringUtils.TRUE)
@MicronautTest(startApplication = false)
class CsrfConfigurationSessionCookieTest {

    @Test
    void whenSettingSessionCookieMaxAgeIgnored(CsrfConfiguration csrfConfiguration) {
        assertTrue(csrfConfiguration.isSessionCookie());
        assertFalse(csrfConfiguration.getCookieMaxAge().isPresent());
    }
}
