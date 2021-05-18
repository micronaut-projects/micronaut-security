package io.micronaut.security.oauth2.docs.openid

import io.micronaut.core.annotation.Nullable;

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import io.micronaut.core.annotation.NonNull
import javax.inject.Singleton

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper.class)
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class GlobalOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    @NonNull
    AuthenticationResponse createAuthenticationResponse(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims, @Nullable State state) {
        new UserDetails("name", [])
    }
}
//end::clazz[]