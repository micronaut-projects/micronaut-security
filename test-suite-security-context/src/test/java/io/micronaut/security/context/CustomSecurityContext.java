package io.micronaut.security.context;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.authentication.Authentication;

/**
 * Test {@link SecurityContext} implementation used to verify supplier SPI loading.
 */
public class CustomSecurityContext implements SecurityContext {
    @Override
    @Nullable
    public Authentication getAuthentication() {
        throw new UnsupportedOperationException();
    }

    @Override
    @Nullable
    public String getToken() {
        throw new UnsupportedOperationException();
    }

    @Override
    @NonNull
    public SecurityContext withAuthentication(@Nullable Authentication authentication) {
        throw new UnsupportedOperationException();
    }

    @Override
    @NonNull
    public SecurityContext withToken(@Nullable String token) {
        throw new UnsupportedOperationException();
    }

    @Override
    @NonNull
    public SecurityContext withRejectionStatus(@Nullable Integer statusCode) {
        throw new UnsupportedOperationException();
    }

    @Override
    @Nullable
    public Integer getRejectionStatus() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void clear() {
        throw new UnsupportedOperationException();
    }
}
