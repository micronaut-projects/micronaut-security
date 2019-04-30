package io.micronaut.security.oauth2.endpoint.token.response;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface TokenResponse {

    /**
     * @return The access token issued by the authorization server.
     */
    @Nonnull
    String getAccessToken();

    /**
     *
     * @return The type of the token issued.
     */
    @Nonnull
    String getTokenType();

    /**
     *
     * @return The lifetime in seconds of the access token.
     */
    @Nullable
    Integer getExpiresIn();

    /**
     *
     * @return Scope of the access token.
     */
    @Nullable
    String getScope();

    /**
     * @return The refresh token, which can be used to obtain new access tokens using the same authorization grant.
     */
    @Nullable
    String getRefreshToken();
}
