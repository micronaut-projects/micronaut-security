package io.micronaut.security.oauth2.configuration;

public interface OpenIdAdditionalClaimsConfiguration {

    /**
     * @return True if the provider's JWT should be included in the Micronaut JWT
     */
    boolean isJwt();

    /**
     * @return True if the provider's access token should be included in the Micronaut JWT
     */
    boolean isAccessToken();

    /**
     * @return True if the provider's refresh token should be included in the Micronaut JWT
     */
    boolean isRefreshToken();
}
