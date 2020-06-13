package io.micronaut.security.oauth2.docs.openid;

//tag::clazz[]
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.security.token.config.TokenConfiguration;

import javax.inject.Named;
import javax.inject.Singleton;

@Singleton
@Named("okta") // <1>
public class OktaAuthenticationMapper implements OpenIdAuthenticationMapper {

    private final TokenConfiguration tokenConfiguration;

    public OktaAuthenticationMapper(TokenConfiguration tokenConfiguration) {
        this.tokenConfiguration = tokenConfiguration;
    }

    @Override
    @NonNull
    public AuthenticationResponse createAuthenticationResponse(String providerName, // <2>
                                                               OpenIdTokenResponse tokenResponse, // <3>
                                                               OpenIdClaims openIdClaims, // <4>
                                                               @Nullable State state) { // <5>
        return AuthenticationResponse.build("name",tokenConfiguration); // <6>
    }
}
//end::clazz[]