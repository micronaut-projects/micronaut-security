package io.micronaut.security.oauth2.endpoint.token.request.password;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.annotation.Nullable;

@Factory
public class PasswordGrantFactory {

    @EachBean(OauthClientConfiguration.class)
    AuthenticationProvider passwordGrantProvider(
            @Parameter OauthClientConfiguration clientConfiguration,
            @Parameter @Nullable OauthUserDetailsMapper userDetailsMapper,
            @Parameter @Nullable OpenIdUserDetailsMapper openIdUserDetailsMapper,
            @Parameter @Nullable OpenIdProviderMetadata openIdProviderMetadata,
            TokenEndpointClient tokenEndpointClient,
            @Nullable OpenIdTokenResponseValidator tokenResponseValidator) {

        if (clientConfiguration.getGrantType() == GrantType.PASSWORD) {
            if (clientConfiguration.getToken().isPresent()) {
                if (userDetailsMapper != null) {
                    return new OauthPasswordAuthenticationProvider(tokenEndpointClient, clientConfiguration, userDetailsMapper);
                }
            } else if (clientConfiguration.getOpenid().isPresent()) {
                if (openIdUserDetailsMapper != null && openIdProviderMetadata != null && tokenResponseValidator != null) {
                    return new OpenIdPasswordAuthenticationProvider(clientConfiguration, openIdProviderMetadata, tokenEndpointClient, openIdUserDetailsMapper, tokenResponseValidator);
                }
            }
        }

        return null;
    }
}
