/*
 * Copyright 2017-2020 original authors
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
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.SecureGrant;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The default implementation of {@link TokenEndpointClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
public class DefaultTokenEndpointClient implements TokenEndpointClient  {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenEndpointClient.class);

    private final BeanContext beanContext;
    private final RxHttpClient defaultTokenClient;
    private final ConcurrentHashMap<String, RxHttpClient> tokenClients = new ConcurrentHashMap<>();

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration
     */
    public DefaultTokenEndpointClient(BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.defaultTokenClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultClientConfiguration);
    }

    @Nonnull
    @Override
    public <G, R extends TokenResponse> Publisher<R> sendRequest(TokenRequestContext<G, R> requestContext) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Sending request to token endpoint [{}]", requestContext.getEndpoint().getUrl());
        }

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
     * Secures the request according to the context's endpoint supported authentication
     * methods.
     *
     * @param request Token endpoint Request
     * @param requestContext The request context
     * @param <G> The token request grant or body
     * @param <R> The token response type
     */
    protected <G, R extends TokenResponse> void secureRequest(@Nonnull MutableHttpRequest<G> request,
                                 TokenRequestContext<G, R> requestContext) {
        List<AuthenticationMethod> authMethodsSupported = requestContext.getEndpoint().getSupportedAuthenticationMethods().orElseGet(() ->
                Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC));

        OauthClientConfiguration clientConfiguration = requestContext.getClientConfiguration();
        if (LOG.isTraceEnabled()) {
            LOG.trace("The token endpoint supports [{}] authentication methods", authMethodsSupported);
        }

        if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_BASIC)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_basic authentication. Adding an Authorization header");
            }
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        } else if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_POST)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_post authentication. The client_id and client_secret will be present in the body");
            }
            request.getBody()
                    .filter(body -> body instanceof SecureGrant)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> {
                        body.setClientId(clientConfiguration.getClientId());
                        body.setClientSecret(clientConfiguration.getClientSecret());
                    });
        } else {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Unsupported or no authentication method. The client_id will be present in the body");
            }
            request.getBody()
                    .filter(body -> body instanceof SecureGrant)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> body.setClientId(clientConfiguration.getClientId()));
        }
    }

    /**
     * Retrieves a client for the given provider.
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the request
     */
    protected RxHttpClient getClient(String providerName) {
        return tokenClients.computeIfAbsent(providerName, (provider) -> {
            Optional<RxHttpClient> client = beanContext.findBean(RxHttpClient.class, Qualifiers.byName(provider));
            return client.orElse(defaultTokenClient);
        });
    }
}
