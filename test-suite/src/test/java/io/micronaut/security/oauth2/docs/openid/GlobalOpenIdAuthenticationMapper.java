package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import io.micronaut.core.annotation.Nullable;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;

import io.micronaut.core.annotation.NonNull;
import jakarta.inject.Singleton;

@Singleton
@Replaces(DefaultOpenIdAuthenticationMapper.class)
public class GlobalOpenIdAuthenticationMapper implements OpenIdAuthenticationMapper {

    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims, @Nullable State state) {
        return AuthenticationResponse.success("name");
    }
}
//end::clazz[]
