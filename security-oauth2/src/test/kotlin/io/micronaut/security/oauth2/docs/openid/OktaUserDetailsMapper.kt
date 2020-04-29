package io.micronaut.security.oauth2.docs.openid

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import javax.inject.Named
import javax.inject.Singleton

@Singleton
@Named("okta") // <1>
class OktaUserDetailsMapper : OpenIdUserDetailsMapper {

    override fun createAuthenticationResponse(providerName: String, // <2>
                                              tokenResponse: OpenIdTokenResponse, // <3>
                                              openIdClaims: OpenIdClaims) // <4>
            : UserDetails {
        return UserDetails("name", emptyList()) // <5>
    }
}
//end::clazz[]