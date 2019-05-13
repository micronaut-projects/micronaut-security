/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.DefaultSecureEndpoint;
import io.micronaut.security.oauth2.endpoint.SecureEndpoint;
import io.micronaut.security.oauth2.endpoint.introspection.DefaultIntrospectionRequestContext;
import io.micronaut.security.oauth2.endpoint.introspection.IntrospectionEndpointClient;
import io.micronaut.security.oauth2.endpoint.introspection.IntrospectionRequest;
import io.micronaut.security.oauth2.endpoint.introspection.IntrospectionRequestContext;
import io.micronaut.security.oauth2.endpoint.introspection.IntrospectionResponse;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;

import javax.annotation.Nullable;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.List;
import java.util.stream.Collectors;

/**
 * {@link OpenIdTokenResponseValidator} implementation which uses the introspection endpoint to validate a token.
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Named("introspection")
@Singleton
public class IntrospectionOpenIdTokenResponseValidator implements OpenIdTokenResponseValidator {

    private final IntrospectionEndpointClient introspectionEndpointClient;

    /**
     *
     * @param introspectionEndpointClient Introspection endpoint client
     */
    public IntrospectionOpenIdTokenResponseValidator(IntrospectionEndpointClient introspectionEndpointClient) {
        this.introspectionEndpointClient = introspectionEndpointClient;
    }

    @Override
    public Publisher<Boolean> validate(OauthClientConfiguration clientConfiguration,
                                   OpenIdProviderMetadata openIdProviderMetadata,
                                   String token,
                                   @Nullable String nonce) {
        IntrospectionRequestContext requestContext = new DefaultIntrospectionRequestContext(getIntrospectionEndpoint(openIdProviderMetadata), clientConfiguration);
        IntrospectionRequest request = new IntrospectionRequest(token);
        Flowable<IntrospectionResponse> introspectionResponseFlowable = Flowable.fromPublisher(introspectionEndpointClient.sendRequest(requestContext, request));
        return introspectionResponseFlowable.map(IntrospectionResponse::isActive);
    }

    /**
     *
     * @param openIdProviderMetadata Open ID provider metadata
     * @return a Secure endpoint for the introspection endpoint
     */
    protected SecureEndpoint getIntrospectionEndpoint(OpenIdProviderMetadata openIdProviderMetadata) {
        List<String> authMethodsSupported = openIdProviderMetadata.getIntrospectionEndpointAuthMethodsSupported();
        List<AuthenticationMethod> authenticationMethods = null;
        if (authMethodsSupported != null) {
            authenticationMethods = authMethodsSupported.stream()
                    .map(String::toUpperCase)
                    .map(AuthenticationMethod::valueOf)
                    .collect(Collectors.toList());
        }
        if (openIdProviderMetadata.getIntrospectionEndpoint() == null) {
            throw new IllegalArgumentException("Cannot use introspection for OpenIdTokenResponseValidator because introspection endoint is null");
        }
        return new DefaultSecureEndpoint(openIdProviderMetadata.getIntrospectionEndpoint(), authenticationMethods);
    }
}
