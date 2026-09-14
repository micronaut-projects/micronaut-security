package io.micronaut.security.config;

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.cookie.SameSite;
import io.micronaut.security.token.cookie.AccessTokenCookieConfiguration;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void sameSiteDefaultsToLaxForAccessTokenAndRefreshTokenCookies() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie"))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }

    @Test
    void cookieSecureHasNoDefault() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie"))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertFalse(accessTokenCookieConfiguration.isCookieSecure().isPresent());

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertFalse(refreshTokenCookieConfiguration.isCookieSecure().isPresent());
        }
    }

    @ParameterizedTest
    @EnumSource(SameSite.class)
    void sameSiteCanBeOverriddenForAccessTokenAndRefreshTokenCookies(SameSite sameSite) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", sameSite.name(),
            "micronaut.security.token.refresh.cookie.cookie-same-site", sameSite.name()
        ))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(sameSite, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(sameSite, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }

    @Test
    void sameSiteCanBeOverriddenIndependently() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.authentication", "cookie",
            "micronaut.security.token.cookie.cookie-same-site", "Strict"
        ))) {
            AccessTokenCookieConfiguration accessTokenCookieConfiguration = ctx.getBean(AccessTokenCookieConfiguration.class);
            assertEquals(SameSite.Strict, accessTokenCookieConfiguration.getCookieSameSite().orElse(null));

            RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = ctx.getBean(RefreshTokenCookieConfiguration.class);
            assertEquals(SameSite.Lax, refreshTokenCookieConfiguration.getCookieSameSite().orElse(null));
        }
    }
}
