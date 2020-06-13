package io.micronaut.security.oauth2.docs.openid

import edu.umd.cs.findbugs.annotations.Nullable;

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper

import edu.umd.cs.findbugs.annotations.NonNull
import io.micronaut.security.token.config.TokenConfiguration

import javax.inject.Singleton

@Singleton
@Replaces(DefaultOpenIdAuthenticationMapper.class)
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class GlobalOpenIdAuthenticationMapper implements OpenIdAuthenticationMapper {

    private final TokenConfiguration tokenConfiguration

    GlobalOpenIdAuthenticationMapper(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration
    }

    @Override
    @NonNull
    AuthenticationResponse createAuthenticationResponse(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims, @Nullable State state) {
        AuthenticationResponse.build('name', tokenConfiguration)
    }
}
//end::clazz[]