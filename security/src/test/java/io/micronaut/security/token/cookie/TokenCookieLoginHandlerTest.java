package io.micronaut.security.token.cookie;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.CarriedTokensAuthentication;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.RedirectService;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.generator.AccessTokenConfiguration;
import io.micronaut.security.token.render.AccessRefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenCookieLoginHandlerTest {
    private static final Authentication PLAIN = Authentication.build("alice", List.of("ROLE_USER"));

    private AccessRefreshTokenGenerator generator;
    private TokenCookieLoginHandler handler;

    @BeforeEach
    void setUp() {
        generator = mock(AccessRefreshTokenGenerator.class);
        when(generator.generate(any(Authentication.class)))
            .thenReturn(Optional.of(new AccessRefreshToken("generated-access", "generated-refresh", "Bearer", 1800)));
        when(generator.generate(anyString(), any(Authentication.class)))
            .thenReturn(Optional.of(new AccessRefreshToken("regenerated-access", "old-refresh", "Bearer", 1800)));
        RedirectConfiguration redirectConfiguration = mock(RedirectConfiguration.class);
        when(redirectConfiguration.isEnabled()).thenReturn(false);
        AccessTokenConfiguration accessTokenConfiguration = mock(AccessTokenConfiguration.class);
        when(accessTokenConfiguration.getExpiration()).thenReturn(1800);
        handler = new TokenCookieLoginHandler(mock(RedirectService.class), redirectConfiguration,
            new TokenCookieConfigurationProperties(), new RefreshTokenCookieConfigurationProperties(null),
            accessTokenConfiguration, generator, null, List.of());
    }

    @Test
    void loginSuccessStoresTheCarriedTokensInsteadOfGeneratingNewOnes() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of("carried-access", "carried-refresh", 3600), HttpRequest.GET("/"));

        assertEquals(HttpStatus.OK, response.getStatus());
        Map<String, Cookie> cookies = cookies(response);
        assertEquals("carried-access", cookies.get("JWT").getValue());
        assertEquals("carried-refresh", cookies.get("JWT_REFRESH_TOKEN").getValue());
        assertEquals(Duration.ofSeconds(3600).getSeconds(), cookies.get("JWT").getMaxAge());
        verify(generator, never()).generate(any(Authentication.class));
    }

    @Test
    void accessCookieMaxAgeFallsBackToTheConfiguredExpirationWhenTheCarriedTokenLifetimeIsUnknown() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of("carried-access", "carried-refresh", null), HttpRequest.GET("/"));

        assertEquals(1800, cookies(response).get("JWT").getMaxAge());
    }

    @Test
    void loginSuccessGeneratesTokensForAPlainAuthentication() {
        MutableHttpResponse<?> response = handler.loginSuccess(PLAIN, HttpRequest.GET("/"));

        Map<String, Cookie> cookies = cookies(response);
        assertEquals("generated-access", cookies.get("JWT").getValue());
        assertEquals("generated-refresh", cookies.get("JWT_REFRESH_TOKEN").getValue());
        assertEquals(1800, cookies.get("JWT").getMaxAge());
    }

    @Test
    void loginSuccessGeneratesTokensWhenTheCarriedAccessTokenIsMissing() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of(null, "carried-refresh", 3600), HttpRequest.GET("/"));

        Map<String, Cookie> cookies = cookies(response);
        assertEquals("generated-access", cookies.get("JWT").getValue());
        assertEquals("generated-refresh", cookies.get("JWT_REFRESH_TOKEN").getValue());
    }

    @Test
    void loginRefreshStoresTheRotatedRefreshTokenRatherThanTheOneUsedToRefresh() {
        MutableHttpResponse<?> response = handler.loginRefresh(CarriedTokensAuthentication.of("new-access", "rotated-refresh", 3600), "old-refresh", HttpRequest.GET("/"));

        Map<String, Cookie> cookies = cookies(response);
        assertEquals("new-access", cookies.get("JWT").getValue());
        assertEquals("rotated-refresh", cookies.get("JWT_REFRESH_TOKEN").getValue());
        verify(generator, never()).generate(anyString(), any(Authentication.class));
    }

    @Test
    void loginRefreshKeepsTheRefreshTokenUsedToRefreshWhenNoneIsCarried() {
        MutableHttpResponse<?> response = handler.loginRefresh(CarriedTokensAuthentication.of("new-access", null, 3600), "old-refresh", HttpRequest.GET("/"));

        assertEquals("old-refresh", cookies(response).get("JWT_REFRESH_TOKEN").getValue());
    }

    @Test
    void loginRefreshGeneratesTokensForAPlainAuthentication() {
        MutableHttpResponse<?> response = handler.loginRefresh(PLAIN, "old-refresh", HttpRequest.GET("/"));

        Map<String, Cookie> cookies = cookies(response);
        assertEquals("regenerated-access", cookies.get("JWT").getValue());
        assertEquals("old-refresh", cookies.get("JWT_REFRESH_TOKEN").getValue());
    }

    @Test
    void carriedTokensAreNotCopiedIntoAnyOtherCookie() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of("carried-access", "carried-refresh", 3600), HttpRequest.GET("/"));

        assertEquals(2, cookies(response).size());
        assertFalse(cookies(response).containsKey("access_token"));
    }

    private static Map<String, Cookie> cookies(MutableHttpResponse<?> response) {
        return response.getCookies().values().stream().collect(Collectors.toMap(Cookie::getName, c -> c));
    }
}
