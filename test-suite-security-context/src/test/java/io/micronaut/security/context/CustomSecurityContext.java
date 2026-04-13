package io.micronaut.security.context;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;

/**
 * Test {@link SecurityContext} implementation used to verify supplier SPI loading.
 */
public class CustomSecurityContext implements SecurityContext {
    @Override
    @Nullable
    public Authentication getAuthentication() {
        return null;
    }

    @Override
    @Nullable
    public String getToken() {
        return null;
    }

    @Override
    public void setAuthentication(@Nullable Authentication authentication) {

    }

    @Override
    public void setToken(@Nullable String token) {

    }

    @Override
    public void setRejectionStatus(@Nullable Integer statusCode) {

    }

    @Override
    @Nullable
    public Integer getRejectionStatus() {
        return null;
    }

    @Override
    public void clear() {

    }
}
