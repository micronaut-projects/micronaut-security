package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.security.authentication.UserDetails;

public interface OpenIdUserDetailsMapper {

    UserDetails createUserDetails(String providerName,
                                  OpenIdTokenResponse tokenResponse,
                                  OpenIdClaims openIdClaims);
}
