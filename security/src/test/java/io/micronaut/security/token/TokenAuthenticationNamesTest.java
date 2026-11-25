package io.micronaut.security.token;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class TokenAuthenticationNamesTest {
    private static final TokenConfiguration DEFAULTS = new TokenConfiguration() { };
    private static final TokenConfiguration EMAIL_NAME_KEY = new TokenConfiguration() {
        @Override
        public String getNameKey() {
            return "email";
        }
    };

    @Test
    void defaultNameKeyKeepsThePrincipalNameEvenIfASubAttributeIsPresent() {
        Authentication authentication = Authentication.build("provider-a:victim", Map.of("sub", "victim"));
        assertSame(authentication, TokenAuthenticationNames.asResolvedFromToken(DEFAULTS, authentication));
    }

    @Test
    void customNameKeyNamesTheAuthenticationAfterTheAttributeKeepingRolesAndAttributes() {
        Authentication authentication = Authentication.build("mapped-name", List.of("ROLE_USER"), Map.of("sub", "subject-id", "email", "sherlock@example.com"));
        Authentication resolved = TokenAuthenticationNames.asResolvedFromToken(EMAIL_NAME_KEY, authentication);
        assertEquals("sherlock@example.com", resolved.getName());
        assertEquals(List.of("ROLE_USER"), List.copyOf(resolved.getRoles()));
        assertEquals(authentication.getAttributes(), resolved.getAttributes());
    }

    @Test
    void customNameKeyFallsBackToThePrincipalNameWhenTheAttributeIsMissing() {
        Authentication authentication = Authentication.build("mapped-name", Map.of("sub", "subject-id"));
        assertSame(authentication, TokenAuthenticationNames.asResolvedFromToken(EMAIL_NAME_KEY, authentication));
    }
}
