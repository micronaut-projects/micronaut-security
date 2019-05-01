package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.Oauth2CodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.Oauth2UserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

public class DefaultOauth2AuthorizationResponseHandler implements Oauth2AuthorizationResponseHandler {

    private final TokenEndpointClient tokenEndpointClient;

    DefaultOauth2AuthorizationResponseHandler(TokenEndpointClient tokenEndpointClient) {
        this.tokenEndpointClient = tokenEndpointClient;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            Oauth2UserDetailsMapper userDetailsMapper,
            SecureEndpoint tokenEndpoint) {

        Oauth2CodeTokenRequestContext context = new Oauth2CodeTokenRequestContext(authorizationResponse, tokenEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(context))
                .switchMap(response -> {
                    return Flowable.fromPublisher(userDetailsMapper.createUserDetails(response))
                            .map(AuthenticationResponse.class::cast);
                });
    }
}
