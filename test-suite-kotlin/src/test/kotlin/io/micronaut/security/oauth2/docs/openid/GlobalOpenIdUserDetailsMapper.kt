package io.micronaut.security.oauth2.docs.openid

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper
import java.lang.UnsupportedOperationException

import javax.inject.Singleton

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper::class)
class GlobalOpenIdUserDetailsMapper : OpenIdUserDetailsMapper {

    //This method is deprecated and will only be called if the createAuthenticationResponse is not implemented
    override fun createUserDetails(providerName: String?, tokenResponse: OpenIdTokenResponse?, openIdClaims: OpenIdClaims?): UserDetails {
        throw UnsupportedOperationException()
    }

    override fun createAuthenticationResponse(providerName: String, tokenResponse: OpenIdTokenResponse, openIdClaims: OpenIdClaims, state: State?): AuthenticationResponse {
        return UserDetails("name", emptyList())
    }
}
//end::clazz[]