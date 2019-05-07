package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import javax.annotation.Nonnull
import javax.inject.Singleton

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper.class)
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class GlobalOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    @Nonnull
    UserDetails createUserDetails(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        new UserDetails("name", [])
    }
}
//end::clazz[]