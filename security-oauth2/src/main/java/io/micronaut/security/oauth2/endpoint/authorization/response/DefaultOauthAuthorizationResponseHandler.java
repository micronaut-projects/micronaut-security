package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OauthCodeTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.OauthUserDetailsMapper;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

public class DefaultOauthAuthorizationResponseHandler implements OauthAuthorizationResponseHandler {

    private final TokenEndpointClient tokenEndpointClient;

    DefaultOauthAuthorizationResponseHandler(TokenEndpointClient tokenEndpointClient) {
        this.tokenEndpointClient = tokenEndpointClient;
    }

    @Override
    public Publisher<AuthenticationResponse> handle(
            AuthorizationResponse authorizationResponse,
            OauthClientConfiguration clientConfiguration,
            OauthUserDetailsMapper userDetailsMapper,
            SecureEndpoint tokenEndpoint) {

        OauthCodeTokenRequestContext context = new OauthCodeTokenRequestContext(authorizationResponse, tokenEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(context))
                .switchMap(response -> {
                    return Flowable.fromPublisher(userDetailsMapper.createUserDetails(response))
                            .map(AuthenticationResponse.class::cast);
                });
    }
}
