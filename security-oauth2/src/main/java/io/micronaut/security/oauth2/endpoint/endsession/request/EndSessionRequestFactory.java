package io.micronaut.security.oauth2.endpoint.endsession.request;

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.endpoint.endsession.response.EndSessionCallbackUrlBuilder;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;

import javax.annotation.Nullable;

@Factory
public class EndSessionRequestFactory {
    public static final String AUTHENTICATION_PROVIDER_OKTA = "okta";
    public static final String AUTHENTICATION_PROVIDER_COGNITO = "cognito";
    public static final String AUTHENTICATION_PROVIDER_AUTH0 = "auth0";


    @EachBean(OpenIdClientConfiguration.class)
    public EndSessionRequest openIdClient(@Parameter OauthClientConfiguration oauthClientConfiguration,
                                          @Parameter OpenIdProviderMetadata openIdProviderMetadata,
                                          @Nullable EndSessionCallbackUrlBuilder endSessionCallbackUrlBuilder) {

        if ( openIdProviderMetadata.getIssuer().contains(AUTHENTICATION_PROVIDER_OKTA)) {
            return new OktaEndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
        } else if (openIdProviderMetadata.getIssuer().contains(AUTHENTICATION_PROVIDER_COGNITO)) {
            return new AwsCognitoEndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
        } else if (openIdProviderMetadata.getIssuer().contains(AUTHENTICATION_PROVIDER_AUTH0)) {
            return new Auth0EndSessionRequest(endSessionCallbackUrlBuilder, oauthClientConfiguration, openIdProviderMetadata);
        }
        return null;
    }
}
