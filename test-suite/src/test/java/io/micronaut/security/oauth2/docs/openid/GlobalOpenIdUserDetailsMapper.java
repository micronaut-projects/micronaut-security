package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;

import edu.umd.cs.findbugs.annotations.NonNull;
import javax.inject.Singleton;
import java.util.Collections;

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper.class)
public class GlobalOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    //This method is deprecated and will only be called if the createAuthenticationResponse is not implemented
    @NonNull
    @Override
    public UserDetails createUserDetails(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        throw new UnsupportedOperationException();
    }

    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims, @Nullable State state) {
        return new UserDetails("name", Collections.emptyList());
    }
}
//end::clazz[]