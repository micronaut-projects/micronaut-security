package io.micronaut.security.oauth2.docs.openid

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import javax.inject.Singleton

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper::class)
class GlobalOpenIdUserDetailsMapper : OpenIdUserDetailsMapper {

    override fun createAuthenticationResponse(providerName: String, tokenResponse: OpenIdTokenResponse, openIdClaims: OpenIdClaims): UserDetails {
        return UserDetails("name", emptyList())
    }
}
//end::clazz[]