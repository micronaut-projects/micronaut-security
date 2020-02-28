package io.micronaut.security.authentication;

import javax.annotation.Nullable;

public class AuthorizationException extends RuntimeException {

    private final Authentication authentication;
    private final boolean forbidden;

    public AuthorizationException(@Nullable Authentication authentication) {
        this.authentication = authentication;
        this.forbidden = authentication != null;
    }

    public boolean isForbidden() {
        return forbidden;
    }

    public Authentication getAuthentication() {
        return authentication;
    }
}
