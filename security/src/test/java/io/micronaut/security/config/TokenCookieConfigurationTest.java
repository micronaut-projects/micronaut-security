package io.micronaut.security.config;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@MicronautTest(startApplication = false)
class TokenCookieConfigurationTest {

    @Test
    void iSessionCookieDefaultsToFalse() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-max-age", "5m"
        ))) {
            TokenCookieConfiguration tokenCookieConfiguration = ctx.getBean(TokenCookieConfiguration.class);
            assertFalse(tokenCookieConfiguration.isSessionCookie());
            assertTrue(tokenCookieConfiguration.getCookieMaxAge().isPresent());
        }

        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.session-cookie", StringUtils.TRUE,
            "micronaut.security.token.cookie.cookie-max-age", "5m"
        ))) {
            TokenCookieConfiguration tokenCookieConfiguration = ctx.getBean(TokenCookieConfiguration.class);
            assertTrue(tokenCookieConfiguration.isSessionCookie());
            // by setting session-cookie to true, the cookie-max-age should be ignored
            assertFalse(tokenCookieConfiguration.getCookieMaxAge().isPresent());
        }

    }
}
