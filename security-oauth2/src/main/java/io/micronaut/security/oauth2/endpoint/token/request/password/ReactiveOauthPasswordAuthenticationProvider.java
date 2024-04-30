/*
 * Copyright 2017-2023 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.oauth2.endpoint.token.request.password;

import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OauthPasswordTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import java.util.Collections;
import java.util.List;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

/**
 * An {@link ReactiveAuthenticationProvider} that delegates to an OAuth 2.0 provider using the
 * password grant flow.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 * @param <T> Request Context Type
 */
public class ReactiveOauthPasswordAuthenticationProvider<T, I, S> implements ReactiveAuthenticationProvider<T, I, S> {

    private final TokenEndpointClient tokenEndpointClient;
    private final SecureEndpoint secureEndpoint;
    private final OauthClientConfiguration clientConfiguration;
    private final OauthAuthenticationMapper authenticationMapper;

    /**
     * @param tokenEndpointClient The token endpoint client
     * @param clientConfiguration The client configuration
     * @param authenticationMapper  The user details mapper
     */
    public ReactiveOauthPasswordAuthenticationProvider(TokenEndpointClient tokenEndpointClient,
                                                       OauthClientConfiguration clientConfiguration,
                                                       OauthAuthenticationMapper authenticationMapper) {
        this.tokenEndpointClient = tokenEndpointClient;
        this.clientConfiguration = clientConfiguration;
        this.authenticationMapper = authenticationMapper;
        this.secureEndpoint = getTokenEndpoint(clientConfiguration);
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {

        OauthPasswordTokenRequestContext context = new OauthPasswordTokenRequestContext(authenticationRequest, secureEndpoint, clientConfiguration);

        return Flux.from(
                        tokenEndpointClient.sendRequest(context))
                .switchMap(response -> Flux.from(authenticationMapper.createAuthenticationResponse(response, null))
                        .map(AuthenticationResponse.class::cast));
    }

    /**
     * Builds the secure endpoint from the client configuration.
     *
     * @param clientConfiguration The client configuration
     * @return The token endpoint
     */
    protected SecureEndpoint getTokenEndpoint(OauthClientConfiguration clientConfiguration) {
        SecureEndpointConfiguration endpointConfiguration = clientConfiguration.getToken()
                .orElseThrow(() -> new IllegalArgumentException("Token endpoint configuration is missing for provider [" + clientConfiguration.getName() + "]"));

        List<AuthenticationMethod> authMethodsSupported = Collections.singletonList(endpointConfiguration.getAuthMethod()
                .orElse(AuthenticationMethod.CLIENT_SECRET_BASIC));

        String url = endpointConfiguration.getUrl().orElseThrow(() ->
                new IllegalArgumentException("Token endpoint URL is null for provider [" + clientConfiguration.getName() + "]"));

        return new DefaultSecureEndpoint(url, authMethodsSupported);
    }

}
