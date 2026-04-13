package io.micronaut.security.context;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class SecurityContextHolderTest {

    @Test
    void returnsEmptySecurityContextWhenNoRequestIsBound() {
        SecurityContext securityContext = SecurityContextHolder.getSecurityContext();

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
    }

    @Test
    void resolvesSecurityContextFromCurrentRequest() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context-holder");
        Authentication authentication = Authentication.build("watson");
        request.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        request.setAttribute(SecurityFilter.TOKEN, "signed-token");

        ServerRequestContext.with(request, () -> {
            SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
            assertSame(authentication, securityContext.getAuthentication());
            assertEquals("signed-token", securityContext.getToken());
        });
    }

    @Test
    void clearContextRemovesAuthenticationAndTokenFromCurrentRequest() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context-holder");
        Authentication authentication = Authentication.build("watson");
        request.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        request.setAttribute(SecurityFilter.TOKEN, "signed-token");

        ServerRequestContext.with(request, () -> {
            SecurityContextHolder.clearContext();
            SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
            assertNull(securityContext.getAuthentication());
            assertNull(securityContext.getToken());
        });
    }

    @Test
    void securityContextHolderAllowsSettingAuthenticationAndToken() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context-holder");
        Authentication authentication = Authentication.build("watson");

        ServerRequestContext.with(request, () -> {
            SecurityContext securityContext = SecurityContextHolder.getSecurityContext();
            securityContext.setAuthentication(authentication);
            securityContext.setToken("signed-token");

            assertSame(authentication, securityContext.getAuthentication());
            assertEquals("signed-token", securityContext.getToken());
            assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
            assertEquals("signed-token", request.getAttribute(SecurityFilter.TOKEN, String.class).orElse(null));
        });
    }
}
