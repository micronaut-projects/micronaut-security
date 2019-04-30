package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.OpenIdTokenEndpointClient;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;
import org.reactivestreams.Publisher;

public interface OpenIdAuthorizationResponseHandler {

    /**
     * @return A Http Response
     */
    Publisher<AuthenticationResponse> handle(AuthorizationResponse authorizationResponse,
                                             OauthClientConfiguration clientConfiguration,
                                             OpenIdProviderMetadata openIdProviderMetadata,
                                             OpenIdTokenEndpointClient<?> tokenEndpointClient,
                                             SecureEndpoint tokenEndpoint);
}
