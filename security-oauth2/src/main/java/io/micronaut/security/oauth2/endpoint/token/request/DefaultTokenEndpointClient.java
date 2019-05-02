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
package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.BeanContext;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenErrorResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.SecureGrant;
import org.reactivestreams.Publisher;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Singleton
public class DefaultTokenEndpointClient implements TokenEndpointClient  {

    private final BeanContext beanContext;
    private final RxHttpClient defaultTokenClient;
    private final ConcurrentHashMap<String, RxHttpClient> tokenClients = new ConcurrentHashMap<>();

    public DefaultTokenEndpointClient(BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.defaultTokenClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultClientConfiguration);
    }

    @Nonnull
    @Override
    public <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext) {
        MutableHttpRequest<G> request = HttpRequest.POST(
                requestContext.getEndpoint().getUrl(),
                requestContext.getGrant())
                .contentType(requestContext.getMediaType())
                .accept(MediaType.APPLICATION_JSON_TYPE);

        secureRequest(request, requestContext);

        return getClient(requestContext.getClientConfiguration().getName())
                .retrieve(request, requestContext.getResponseType(), requestContext.getErrorResponseType());
    }

    /**
     *
     * @param request Token endpoint Request
     * @return a HTTP Request to the Token Endpoint with Authorization Code Grant payload.
     */
    protected <G, R extends TokenResponse> void secureRequest(@Nonnull MutableHttpRequest<G> request,
                                 TokenRequestContext<G, R> requestContext) {
        List<AuthenticationMethod> authMethodsSupported = requestContext.getEndpoint().getSupportedAuthenticationMethods().orElseGet(() ->
                Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC));

        OauthClientConfiguration clientConfiguration = requestContext.getClientConfiguration();

        if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_BASIC)) {
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        } else if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_POST)) {
            request.getBody()
                    .filter(body -> body instanceof SecureGrant)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> {
                        body.setClientId(clientConfiguration.getClientId());
                        body.setClientSecret(clientConfiguration.getClientSecret());
                    });
        } else {
            request.getBody()
                    .filter(body -> body instanceof SecureGrant)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> body.setClientId(clientConfiguration.getClientId()));
        }
    }

    protected RxHttpClient getClient(String providerName) {
        return tokenClients.computeIfAbsent(providerName, (provider) -> {
            Optional<RxHttpClient> client = beanContext.findBean(RxHttpClient.class, Qualifiers.byName(provider));
            return client.orElse(defaultTokenClient);
        });
    }
}
