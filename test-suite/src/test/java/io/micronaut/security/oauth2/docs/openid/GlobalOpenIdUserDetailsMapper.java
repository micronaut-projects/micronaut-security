package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;

import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;
import java.util.Collections;

@Singleton
@Replaces(DefaultOpenIdUserDetailsMapper.class)
public class GlobalOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {
    
    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims, @Nullable State state) {
        return new UserDetails("name", Collections.emptyList());
    }
}
//end::clazz[]