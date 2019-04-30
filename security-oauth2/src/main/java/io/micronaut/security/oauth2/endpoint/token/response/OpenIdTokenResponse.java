package io.micronaut.security.oauth2.endpoint.token.response;

import javax.annotation.Nonnull;

public interface OpenIdTokenResponse extends TokenResponse {

    @Nonnull
    String getIdToken();
}
