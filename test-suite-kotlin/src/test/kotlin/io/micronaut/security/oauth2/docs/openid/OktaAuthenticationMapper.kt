package io.micronaut.security.oauth2.docs.openid

//tag::clazz[]

import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import jakarta.inject.Named
import jakarta.inject.Singleton

@Singleton
@Named("okta") // <1>
class OktaAuthenticationMapper : OpenIdAuthenticationMapper {

    override fun createAuthenticationResponse(providerName: String, // <2>
                                              tokenResponse: OpenIdTokenResponse, // <3>
                                              openIdClaims: OpenIdClaims, // <4>
                                              state: State?) // <5>
            : AuthenticationResponse {
        return AuthenticationResponse.success("name") // <6>
    }
}
//end::clazz[]
