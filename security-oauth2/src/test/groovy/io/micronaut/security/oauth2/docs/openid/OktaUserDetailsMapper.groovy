package io.micronaut.security.oauth2.docs.openid

import io.micronaut.context.annotation.Requires;

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import javax.annotation.Nonnull
import javax.inject.Named
import javax.inject.Singleton

@Singleton
@Named("okta") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class OktaUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    @Nonnull
    UserDetails createUserDetails(String providerName, // <2>
                                  OpenIdTokenResponse tokenResponse, // <3>
                                  OpenIdClaims openIdClaims) { // <4>
        new UserDetails("name", []) // <5>
    }
}
//end::clazz[]