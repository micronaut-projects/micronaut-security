package io.micronaut.security.oauth2.docs.openid

import io.micronaut.core.annotation.Nullable
import io.micronaut.context.annotation.Requires
import io.micronaut.security.authentication.AuthenticationResponse;

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.oauth2.endpoint.authorization.state.State
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper

import io.micronaut.core.annotation.NonNull
import javax.inject.Named
import javax.inject.Singleton

@Singleton
@Named("okta") // <1>
//end::clazz[]
@Requires(property = "docs.classes")
//tag::clazz[]
class OktaUserDetailsMapper implements OpenIdUserDetailsMapper {

    //This method is deprecated and will only be called if the createAuthenticationResponse is not implemented
    @NonNull
    UserDetails createUserDetails(String providerName,
                                  OpenIdTokenResponse tokenResponse,
                                  OpenIdClaims openIdClaims) {
        throw new UnsupportedOperationException()
    }

    @Override
    @NonNull
    AuthenticationResponse createAuthenticationResponse(String providerName, // <2>
                                                        OpenIdTokenResponse tokenResponse, // <3>
                                                        OpenIdClaims openIdClaims, // <4>
                                                        @Nullable State state) { // <5>
        new UserDetails("name", []) // <6>
    }
}
//end::clazz[]