package io.micronaut.security.docs.customauthentication;

import io.micronaut.security.authentication.Authentication;
import io.micronaut.serde.annotation.Serdeable;

@Serdeable
public record AuthenticationWithEmail(String username,
                                      String email) {
    public static AuthenticationWithEmail of(Authentication authentication) {
        Object obj = authentication.getAttributes().get("email");
        String email = obj == null ? null : obj.toString();
        return new AuthenticationWithEmail(authentication.getName(), email);
    }
}
