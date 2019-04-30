package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.BeanContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.DefaultTokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import org.reactivestreams.Publisher;

import javax.inject.Singleton;

@Singleton
public class DefaultOauth2TokenEndpointClient extends AbstractTokenEndpointClient<TokenResponse> implements Oauth2TokenEndpointClient<TokenResponse> {

    public DefaultOauth2TokenEndpointClient(BeanContext beanContext,
                                            HttpClientConfiguration defaultClientConfiguration) {
        super(beanContext, defaultClientConfiguration);
    }

    @Override
    protected Publisher<TokenResponse> doSend(MutableHttpRequest<AuthorizationCodeGrant> request,
                                              OauthClientConfiguration clientConfiguration) {
        return getClient(clientConfiguration.getName())
                .retrieve(request, Argument.of(DefaultTokenResponse.class), Argument.of(DefaultTokenErrorResponse.class))
                .map(TokenResponse.class::cast);
    }

    @Override
    protected MediaType getMediaType(OauthClientConfiguration clientConfiguration) {
        return MediaType.APPLICATION_FORM_URLENCODED_TYPE;
    }
}
