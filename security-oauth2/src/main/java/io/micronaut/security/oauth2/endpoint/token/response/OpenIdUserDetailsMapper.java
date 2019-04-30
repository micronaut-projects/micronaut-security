package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;

public interface OpenIdUserDetailsMapper {

    String OPENID_TOKEN_KEY = "openIdToken";

    UserDetails createUserDetails(String providerName,
                                  OpenIdTokenResponse tokenResponse,
                                  OpenIdClaims openIdClaims);
}
