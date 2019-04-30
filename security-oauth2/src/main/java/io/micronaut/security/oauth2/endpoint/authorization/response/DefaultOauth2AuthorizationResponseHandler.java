package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.Oauth2TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.response.Oauth2UserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

public class DefaultOauth2AuthorizationResponseHandler implements Oauth2AuthorizationResponseHandler {

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            Oauth2UserDetailsMapper userDetailsMapper,
            Oauth2TokenEndpointClient<?> tokenEndpointClient,
            SecureEndpoint tokenEndpoint) {

        return Flowable.fromPublisher(tokenEndpointClient
                .sendRequest(authorizationResponse, clientConfiguration, tokenEndpoint))
                .switchMap(response -> {
                    return Flowable.fromPublisher(userDetailsMapper.createUserDetails(response))
                            .map(AuthenticationResponse.class::cast);
                });
    }
}
