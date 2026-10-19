package io.micronaut.security.token.bearer;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.CarriedTokensAuthentication;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.render.AccessRefreshToken;
import io.micronaut.security.token.render.BearerAccessRefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessRefreshTokenLoginHandlerTest {
    private static final Authentication PLAIN = Authentication.build("alice", List.of("ROLE_USER"));

    private AccessRefreshTokenGenerator generator;
    private AccessRefreshTokenLoginHandler handler;

    @BeforeEach
    void setUp() {
        generator = mock(AccessRefreshTokenGenerator.class);
        when(generator.generate(any(Authentication.class)))
            .thenReturn(Optional.of(new AccessRefreshToken("generated-access", "generated-refresh", "Bearer", 1800)));
        when(generator.generate(anyString(), any(Authentication.class)))
            .thenReturn(Optional.of(new AccessRefreshToken("regenerated-access", "old-refresh", "Bearer", 1800)));
        handler = new AccessRefreshTokenLoginHandler(generator);
    }

    @Test
    void loginSuccessRendersTheCarriedTokensWithThePrincipalNameAndRoles() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of("carried-access", "carried-refresh", 3600), HttpRequest.GET("/"));

        assertEquals(HttpStatus.OK, response.getStatus());
        BearerAccessRefreshToken body = assertInstanceOf(BearerAccessRefreshToken.class, response.body());
        assertEquals("carried-access", body.getAccessToken());
        assertEquals("carried-refresh", body.getRefreshToken());
        assertEquals(3600, body.getExpiresIn());
        assertEquals("Bearer", body.getTokenType());
        assertEquals("alice", body.getUsername());
        assertEquals(List.of("ROLE_USER"), List.copyOf(body.getRoles()));
        verify(generator, never()).generate(any(Authentication.class));
    }

    @Test
    void loginSuccessGeneratesTokensForAPlainAuthentication() {
        MutableHttpResponse<?> response = handler.loginSuccess(PLAIN, HttpRequest.GET("/"));

        AccessRefreshToken body = assertInstanceOf(AccessRefreshToken.class, response.body());
        assertEquals("generated-access", body.getAccessToken());
    }

    @Test
    void loginSuccessGeneratesTokensWhenTheCarriedAccessTokenIsBlank() {
        MutableHttpResponse<?> response = handler.loginSuccess(CarriedTokensAuthentication.of("", "carried-refresh", 3600), HttpRequest.GET("/"));

        AccessRefreshToken body = assertInstanceOf(AccessRefreshToken.class, response.body());
        assertEquals("generated-access", body.getAccessToken());
    }

    @Test
    void loginRefreshRendersTheRotatedRefreshToken() {
        MutableHttpResponse<?> response = handler.loginRefresh(CarriedTokensAuthentication.of("new-access", "rotated-refresh", 3600), "old-refresh", HttpRequest.GET("/"));

        AccessRefreshToken body = assertInstanceOf(AccessRefreshToken.class, response.body());
        assertEquals("new-access", body.getAccessToken());
        assertEquals("rotated-refresh", body.getRefreshToken());
        verify(generator, never()).generate(anyString(), any(Authentication.class));
    }

    @Test
    void loginRefreshKeepsTheRefreshTokenUsedToRefreshWhenNoneIsCarried() {
        MutableHttpResponse<?> response = handler.loginRefresh(CarriedTokensAuthentication.of("new-access", null, null), "old-refresh", HttpRequest.GET("/"));

        AccessRefreshToken body = assertInstanceOf(AccessRefreshToken.class, response.body());
        assertEquals("old-refresh", body.getRefreshToken());
        assertNull(body.getExpiresIn());
    }

    @Test
    void loginRefreshGeneratesTokensForAPlainAuthentication() {
        MutableHttpResponse<?> response = handler.loginRefresh(PLAIN, "old-refresh", HttpRequest.GET("/"));

        AccessRefreshToken body = assertInstanceOf(AccessRefreshToken.class, response.body());
        assertEquals("regenerated-access", body.getAccessToken());
    }
}
