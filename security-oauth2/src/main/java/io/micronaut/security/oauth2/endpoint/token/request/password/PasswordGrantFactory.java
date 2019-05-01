package io.micronaut.security.oauth2.endpoint.token.request.password;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.response.Oauth2UserDetailsMapper;
import io.micronaut.security.oauth2.grants.GrantType;

@Factory
public class PasswordGrantFactory {

    @EachBean(OauthClientConfiguration.class)
    AuthenticationProvider passwordGrantProvider(
            @Parameter OauthClientConfiguration clientConfiguration,
            @Parameter Oauth2UserDetailsMapper userDetailsMapper,
            TokenEndpointClient tokenEndpointClient) {
        if (clientConfiguration.getGrantType() == GrantType.PASSWORD && clientConfiguration.getToken().isPresent()) {
            return new GrantTypePasswordAuthenticationProvider(tokenEndpointClient, clientConfiguration, userDetailsMapper);
        } else {
            return null;
        }
    }
}
