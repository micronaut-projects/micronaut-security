package io.micronaut.security.oauth2.handlers;

public enum RedirectionStrategy {

    /**
     * Redirect back to the original location before redirection.
     */
    ORIGINAL,

    /**
     * Redirect to a statically configured URI.
     */
    STATIC
}
