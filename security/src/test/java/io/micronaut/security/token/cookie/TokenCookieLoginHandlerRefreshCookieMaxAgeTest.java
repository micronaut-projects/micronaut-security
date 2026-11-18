package io.micronaut.security.token.cookie;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import io.micronaut.security.token.render.AccessRefreshToken;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TokenCookieLoginHandlerRefreshCookieMaxAgeTest {

    private static final AccessRefreshToken ACCESS_REFRESH_TOKEN = new AccessRefreshToken("access", "refresh", "Bearer", 3600);

    @Test
    void refreshCookieMaxAgeFallsBackToThirtyDaysWhenConfigurationHasNone() {
        RefreshTokenCookieConfiguration refreshTokenCookieConfiguration = mock(RefreshTokenCookieConfiguration.class);
        when(refreshTokenCookieConfiguration.getCookieName()).thenReturn("JWT_REFRESH_TOKEN");
        when(refreshTokenCookieConfiguration.getCookieMaxAge()).thenReturn(Optional.empty());

        Optional<Cookie> cookie = loginHandler(refreshTokenCookieConfiguration).refreshTokenCookie(ACCESS_REFRESH_TOKEN, mock(HttpRequest.class));

        assertTrue(cookie.isPresent());
        assertEquals(Duration.ofDays(30).toSeconds(), cookie.get().getMaxAge());
    }

    @Test
    void refreshCookieUsesConfiguredMaxAge() {
        RefreshTokenCookieConfigurationProperties refreshTokenCookieConfiguration = new RefreshTokenCookieConfigurationProperties(null);
        refreshTokenCookieConfiguration.setCookieMaxAge(Duration.ofMinutes(10));

        Optional<Cookie> cookie = loginHandler(refreshTokenCookieConfiguration).refreshTokenCookie(ACCESS_REFRESH_TOKEN, mock(HttpRequest.class));

        assertTrue(cookie.isPresent());
        assertEquals(Duration.ofMinutes(10).toSeconds(), cookie.get().getMaxAge());
    }

    private static TokenCookieLoginHandler loginHandler(RefreshTokenCookieConfiguration refreshTokenCookieConfiguration) {
        RedirectConfiguration redirectConfiguration = mock(RedirectConfiguration.class);
        when(redirectConfiguration.isEnabled()).thenReturn(false);
        return new TokenCookieLoginHandler(mock(RedirectService.class),
            redirectConfiguration,
            new TokenCookieConfigurationProperties(),
            refreshTokenCookieConfiguration,
            mock(AccessTokenConfiguration.class),
            mock(AccessRefreshTokenGenerator.class),
            null,
            List.of());
    }
}
