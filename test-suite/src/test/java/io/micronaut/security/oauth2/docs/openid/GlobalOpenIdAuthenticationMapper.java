package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultOpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.token.config.TokenConfiguration;

import javax.inject.Singleton;

@Singleton
@Replaces(DefaultOpenIdAuthenticationMapper.class)
public class GlobalOpenIdAuthenticationMapper implements OpenIdAuthenticationMapper {

    private final TokenConfiguration tokenConfiguration;

    public GlobalOpenIdAuthenticationMapper(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(String providerName,
                                                               OpenIdTokenResponse tokenResponse,
                                                               OpenIdClaims openIdClaims,
                                                               @Nullable State state) {
        return AuthenticationResponse.build("name", tokenConfiguration);
    }
}
//end::clazz[]