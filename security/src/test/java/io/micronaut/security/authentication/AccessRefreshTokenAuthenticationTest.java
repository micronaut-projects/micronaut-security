package io.micronaut.security.authentication;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class AccessRefreshTokenAuthenticationTest {

    @Test
    void nameRolesAndAttributesDelegateToTheWrappedAuthentication() {
        Authentication delegate = Authentication.build("alice", List.of("ROLE_USER"), Map.of("email", "alice@example.com"));
        AccessRefreshTokenAuthentication authentication = new CarriedTokensAuthentication("access", "refresh", 3600, delegate);

        assertEquals("alice", authentication.getName());
        assertEquals(List.of("ROLE_USER"), List.copyOf(authentication.getRoles()));
        assertEquals("alice@example.com", authentication.getAttributes().get("email"));
    }

    @Test
    void tokensAreNotExposedAsAttributes() {
        AccessRefreshTokenAuthentication authentication = CarriedTokensAuthentication.of("access", "refresh", 3600);

        assertFalse(authentication.getAttributes().containsValue("access"));
        assertFalse(authentication.getAttributes().containsValue("refresh"));
        assertEquals("access", authentication.getAccessToken());
        assertEquals("refresh", authentication.getRefreshToken());
        assertEquals(3600, authentication.getExpiresIn());
    }

    @Test
    void expiresInDefaultsToNull() {
        AccessRefreshTokenAuthentication authentication = new AccessRefreshTokenAuthentication() {
            @Override
            public String getAccessToken() {
                return "access";
            }

            @Override
            public String getRefreshToken() {
                return null;
            }

            @Override
            public Authentication getAuthentication() {
                return Authentication.build("alice");
            }
        };

        assertNull(authentication.getExpiresIn());
        assertNull(authentication.getRefreshToken());
    }
}
