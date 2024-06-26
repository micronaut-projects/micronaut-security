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

import com.nimbusds.jwt.JWT;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OpenIdPasswordTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdAuthenticationMapper;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.validation.ReactiveOpenIdTokenResponseValidator;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An {@link ReactiveAuthenticationProvider} that delegates to an OpenID provider using the
 * password grant flow.
 *
 * @author Sergio del Amo
 * @since 4.8.0
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
public class ReactiveOpenIdPasswordAuthenticationProvider<T, I, S> implements ReactiveAuthenticationProvider<T, I, S> {

    private final TokenEndpointClient tokenEndpointClient;
    private final SecureEndpoint secureEndpoint;
    private final OauthClientConfiguration clientConfiguration;
    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final OpenIdAuthenticationMapper openIdAuthenticationMapper;
    private final ReactiveOpenIdTokenResponseValidator<JWT> tokenResponseValidator;

    /**
     * @param clientConfiguration        The client configuration
     * @param openIdProviderMetadata     The provider metadata
     * @param tokenEndpointClient        The token endpoint client
     * @param openIdAuthenticationMapper The user details mapper
     * @param tokenResponseValidator     The token response validator
     */
    public ReactiveOpenIdPasswordAuthenticationProvider(OauthClientConfiguration clientConfiguration,
                                                        OpenIdProviderMetadata openIdProviderMetadata,
                                                        TokenEndpointClient tokenEndpointClient,
                                                        OpenIdAuthenticationMapper openIdAuthenticationMapper,
                                                        ReactiveOpenIdTokenResponseValidator<JWT> tokenResponseValidator) {
        this.tokenEndpointClient = tokenEndpointClient;
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.openIdAuthenticationMapper = openIdAuthenticationMapper;
        this.tokenResponseValidator = tokenResponseValidator;
        this.secureEndpoint = getTokenEndpoint(openIdProviderMetadata);
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        OpenIdPasswordTokenRequestContext openIdPasswordTokenRequestContext = new OpenIdPasswordTokenRequestContext(authenticationRequest, secureEndpoint, clientConfiguration);
        return Flux.from(tokenEndpointClient.sendRequest(openIdPasswordTokenRequestContext))
                   .flatMap(openIdTokenResponse ->
                                Flux.from(tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, openIdTokenResponse, null))
                                    .flatMap(jwt -> {
                                        try {
                                            OpenIdClaims claims = new JWTOpenIdClaims(jwt.getJWTClaimsSet());
                                            return openIdAuthenticationMapper.createAuthenticationResponse(clientConfiguration.getName(), openIdTokenResponse, claims, null);
                                        } catch (ParseException e) {
                                            // Should never happen as validation succeeded
                                            return Flux.error(e);
                                        }
                                    })
                   );
    }

    /**
     * Builds the secure endpoint from the provider metadata.
     *
     * @param openIdProviderMetadata The provider metadata
     * @return The token endpoint
     */
    private static SecureEndpoint getTokenEndpoint(OpenIdProviderMetadata openIdProviderMetadata) {
        List<String> authMethodsSupported = openIdProviderMetadata.getTokenEndpointAuthMethodsSupported();
        List<AuthenticationMethod> authenticationMethods = null;
        if (authMethodsSupported != null) {
            authenticationMethods = authMethodsSupported.stream()
                    .map(String::toUpperCase)
                    .map(AuthenticationMethod::valueOf)
                    .collect(Collectors.toList());
        }
        return new DefaultSecureEndpoint(openIdProviderMetadata.getTokenEndpoint(), authenticationMethods);
    }
}
