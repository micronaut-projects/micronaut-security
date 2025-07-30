package io.micronaut.security.endpoints;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.http.cookie.Cookies;
import io.micronaut.security.token.cookie.RefreshTokenCookieConfiguration;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OauthControllerTest {

    @Test
    void testRefreshCookieValueDefaultCookieName() {
        HttpRequest<?> request = mock(HttpRequest.class);
        Cookies cookies = mock(Cookies.class);
        Cookie cookie = mock(Cookie.class);

        when(request.getCookies()).thenReturn(cookies);
        when(cookies.findCookie("JWT_REFRESH_TOKEN")).thenReturn(Optional.of(cookie));
        when(cookie.getValue()).thenReturn("cookie-value");

        String result = OauthController.refreshCookieValue(request, null);
        assertEquals("cookie-value", result);
    }

    @Test
    void testRefreshCookieValueWithCookiePresent() {
        HttpRequest<?> request = mock(HttpRequest.class);
        Cookies cookies = mock(Cookies.class);
        Cookie cookie = mock(Cookie.class);
        RefreshTokenCookieConfiguration config = mock(RefreshTokenCookieConfiguration.class);

        when(config.getCookieName()).thenReturn("MY_REFRESH_TOKEN");
        when(request.getCookies()).thenReturn(cookies);
        when(cookies.findCookie("MY_REFRESH_TOKEN")).thenReturn(Optional.of(cookie));
        when(cookie.getValue()).thenReturn("cookie-value");

        String result = OauthController.refreshCookieValue(request, config);
        assertEquals("cookie-value", result);
    }

    @Test
    void testRefreshCookieValueWithCookieAbsent() {
        HttpRequest<?> request = mock(HttpRequest.class);
        Cookies cookies = mock(Cookies.class);
        RefreshTokenCookieConfiguration config = mock(RefreshTokenCookieConfiguration.class);

        when(config.getCookieName()).thenReturn("MY_REFRESH_TOKEN");
        when(request.getCookies()).thenReturn(cookies);
        when(cookies.findCookie("MY_REFRESH_TOKEN")).thenReturn(Optional.empty());

        String result = OauthController.refreshCookieValue(request, config);
        assertNull(result);
    }
}
