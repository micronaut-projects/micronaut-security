package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;

import javax.annotation.Nonnull;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Collections;

@Singleton
@Named("okta") // <1>
public class OktaUserDetailsMapper implements OpenIdUserDetailsMapper {

    @Override
    @Nonnull
    public UserDetails createUserDetails(String providerName, // <2>
                                         OpenIdTokenResponse tokenResponse, // <3>
                                         OpenIdClaims openIdClaims) { // <4>
        return new UserDetails("name", Collections.emptyList()); // <5>
    }
}
//end::clazz[]