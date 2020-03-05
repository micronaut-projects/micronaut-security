/*
 * Copyright 2017-2020 original authors
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
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.OpenIdPasswordTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdUserDetailsMapper;
import io.micronaut.security.oauth2.endpoint.token.response.validation.OpenIdTokenResponseValidator;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * An {@link AuthenticationProvider} that delegates to an OpenID provider using the
 * password grant flow.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
public class OpenIdPasswordAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(OauthPasswordAuthenticationProvider.class);

    private final TokenEndpointClient tokenEndpointClient;
    private final SecureEndpoint secureEndpoint;
    private final OauthClientConfiguration clientConfiguration;
    private final OpenIdProviderMetadata openIdProviderMetadata;
    private final OpenIdUserDetailsMapper openIdUserDetailsMapper;
    private final OpenIdTokenResponseValidator tokenResponseValidator;

    /**
     * @param clientConfiguration The client configuration
     * @param openIdProviderMetadata The provider metadata
     * @param tokenEndpointClient The token endpoint client
     * @param openIdUserDetailsMapper The user details mapper
     * @param tokenResponseValidator The token response validator
     */
    public OpenIdPasswordAuthenticationProvider(OauthClientConfiguration clientConfiguration,
                                                OpenIdProviderMetadata openIdProviderMetadata,
                                                TokenEndpointClient tokenEndpointClient,
                                                OpenIdUserDetailsMapper openIdUserDetailsMapper,
                                                OpenIdTokenResponseValidator tokenResponseValidator) {
        this.tokenEndpointClient = tokenEndpointClient;
        this.clientConfiguration = clientConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.openIdUserDetailsMapper = openIdUserDetailsMapper;
        this.tokenResponseValidator = tokenResponseValidator;

        Optional<TokenEndpointConfiguration> tokenEndpointConfiguration = clientConfiguration.getOpenid().flatMap(OpenIdClientConfiguration::getToken);
        if (!tokenEndpointConfiguration.isPresent()) {
            throw new IllegalArgumentException("Missing token endpoint configuration");
        }
        this.secureEndpoint = getTokenEndpoint(openIdProviderMetadata);
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(AuthenticationRequest authenticationRequest) {

        OpenIdPasswordTokenRequestContext requestContext = new OpenIdPasswordTokenRequestContext(authenticationRequest, secureEndpoint, clientConfiguration);

        return Flowable.fromPublisher(
                tokenEndpointClient.sendRequest(requestContext))
                .switchMap(response -> {
                    return Flowable.create(emitter -> {
                        Optional<JWT> jwt = tokenResponseValidator.validate(clientConfiguration, openIdProviderMetadata, response, null);
                        if (jwt.isPresent()) {
                            try {
                                OpenIdClaims claims = new JWTOpenIdClaims(jwt.get().getJWTClaimsSet());
                                emitter.onNext(openIdUserDetailsMapper.createUserDetails(clientConfiguration.getName(), response, claims));
                                emitter.onComplete();
                            } catch (ParseException e) {
                                //Should never happen as validation succeeded
                                emitter.onError(e);
                            }
                        } else {
                            emitter.onNext(new AuthenticationFailed("JWT validation failed"));
                            emitter.onComplete();
                        }
                    }, BackpressureStrategy.ERROR);
                });
    }

    /**
     * Builds the secure endpoint from the provider metadata
     *
     * @param openIdProviderMetadata The provider metadata
     * @return The token endpoint
     */
    protected SecureEndpoint getTokenEndpoint(OpenIdProviderMetadata openIdProviderMetadata) {
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
