package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

/**
 * Defines an authentication provider.
 * @since 4.5.0
 * @param <T> Request
 */
@FunctionalInterface
public interface BlockingAuthenticationProvider<T> {
    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link Authentication}.
     *
     * Publishers <b>MUST emit cold observables</b>! This method will be called for
     * all authenticators for each authentication request and it is assumed no work
     * will be done until the publisher is subscribed to.
     *
     * @param httpRequest The http request
     * @param authenticationRequest The credentials to authenticate
     * @return A publisher that emits 0 or 1 responses
     */
    @NonNull
    @Blocking
    AuthenticationResponse authenticate(@Nullable T httpRequest, AuthenticationRequest<?, ?> authenticationRequest);
}
