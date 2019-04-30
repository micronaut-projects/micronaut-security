package io.micronaut.security.oauth2.configuration.endpoints;


import javax.annotation.Nonnull;

public interface EndSessionConfiguration {

    @Nonnull
    String getViewModelKey();

    @Nonnull
    String getRedirectUri();

}
