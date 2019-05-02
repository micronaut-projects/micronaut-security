package io.micronaut.security.oauth2.configuration.endpoints;


import javax.annotation.Nonnull;

/**
 * @author James Kleeh
 * @since 1.0.0
 */
public interface EndSessionConfiguration {

    @Nonnull
    String getViewModelKey();

    /**
     *
     * @return the redirect uri
     */
    @Nonnull
    String getRedirectUri();

}
