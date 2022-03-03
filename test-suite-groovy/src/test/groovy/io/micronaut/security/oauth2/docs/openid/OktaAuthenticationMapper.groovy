package io.micronaut.security.oauth2.docs.openid

import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.NonNull
import io.micronaut.core.annotation.Nullable
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State;

//tag::clazz[]

import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import jakarta.inject.Named
import jakarta.inject.Singleton

@Singleton
@Named("okta") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class OktaAuthenticationMapper implements OpenIdAuthenticationMapper {

    @Override
    @NonNull
    AuthenticationResponse createAuthenticationResponse(String providerName, // <2>
                                                        OpenIdTokenResponse tokenResponse, // <3>
                                                        OpenIdClaims openIdClaims, // <4>
                                                        @Nullable State state) { // <5>
        AuthenticationResponse.success("name") // <6>
    }
}
//end::clazz[]
