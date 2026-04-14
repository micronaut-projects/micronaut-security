package io.micronaut.security.context;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.SecurityFilter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class MutableAttributeHolderSecurityContextTest {

    @Test
    void returnsNullAuthenticationAndTokenWhenAttributeHolderIsNull() {
        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(null);

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
    }

    @Test
    void returnsNullAuthenticationAndTokenWhenAttributesAreMissing() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context");
        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);

        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
    }

    @Test
    void resolvesAuthenticationAndTokenFromRequestAttributes() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context");
        Authentication authentication = Authentication.build("sherlock");
        request.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        request.setAttribute(SecurityFilter.TOKEN, "jwt-token");

        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);

        assertEquals(authentication, securityContext.getAuthentication());
        assertEquals("jwt-token", securityContext.getToken());
    }

    @Test
    void settersWriteAuthenticationAndTokenToAttributeHolder() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context");
        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);
        Authentication authentication = Authentication.build("sherlock");

        securityContext.withAuthentication(authentication)
            .withToken("jwt-token");

        assertSame(authentication, request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        assertEquals("jwt-token", request.getAttribute(SecurityFilter.TOKEN, String.class).orElse(null));
        assertSame(authentication, securityContext.getAuthentication());
        assertEquals("jwt-token", securityContext.getToken());
    }

    @Test
    void setRejectionStatusWritesHttpStatusToAttributeHolder() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context");
        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);

        securityContext.withRejectionStatus(HttpStatus.UNAUTHORIZED.getCode());

        assertSame(HttpStatus.UNAUTHORIZED, request.getAttribute(SecurityFilter.REJECTION, HttpStatus.class).orElse(null));
    }

    @Test
    void settersAcceptNullToClearValues() {
        MutableHttpRequest<?> request = HttpRequest.GET("/context");
        Authentication authentication = Authentication.build("sherlock");
        request.setAttribute(SecurityFilter.AUTHENTICATION, authentication);
        request.setAttribute(SecurityFilter.TOKEN, "jwt-token");
        request.setAttribute(SecurityFilter.REJECTION, HttpStatus.UNAUTHORIZED);
        MutableAttributeHolderSecurityContext securityContext = new MutableAttributeHolderSecurityContext(request);

        securityContext.withAuthentication(null)
            .withToken(null);
        securityContext.clear();

        assertNull(request.getAttribute(SecurityFilter.AUTHENTICATION, Authentication.class).orElse(null));
        assertNull(request.getAttribute(SecurityFilter.TOKEN, String.class).orElse(null));
        assertNull(request.getAttribute(SecurityFilter.REJECTION, HttpStatus.class).orElse(null));
        assertNull(securityContext.getAuthentication());
        assertNull(securityContext.getToken());
    }
}
