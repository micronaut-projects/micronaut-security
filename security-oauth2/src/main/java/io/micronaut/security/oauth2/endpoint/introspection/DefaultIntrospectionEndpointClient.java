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
package io.micronaut.security.oauth2.endpoint.introspection;

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
import io.micronaut.validation.Validated;
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
 * The default implementation of {@link IntrospectionEndpointClient}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Singleton
@Validated
public class DefaultIntrospectionEndpointClient implements IntrospectionEndpointClient  {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultIntrospectionEndpointClient.class);

    private final BeanContext beanContext;
    private final RxHttpClient defaultIntrospectionClient;
    private final ConcurrentHashMap<String, RxHttpClient> introspectionClients = new ConcurrentHashMap<>();

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration
     */
    public DefaultIntrospectionEndpointClient(BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.defaultIntrospectionClient = beanContext.createBean(RxHttpClient.class, LoadBalancer.empty(), defaultClientConfiguration);
    }

    @Nonnull
    @Override
    public Publisher<IntrospectionResponse> sendRequest(IntrospectionRequestContext requestContext, IntrospectionRequest introspectionRequest) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Sending request to introspectionendpoint endpoint [{}]", requestContext.getEndpoint().getUrl());
        }

        MutableHttpRequest<?> request = HttpRequest.POST(requestContext.getEndpoint().getUrl(), introspectionRequest.toMap())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED);

        secureRequest(requestContext, request);

        return getClient(requestContext.getClientConfiguration().getName()).retrieve(request, IntrospectionResponse.class);
    }

    /**
     * Decorate the request
     * @param requestContext Introspection request context
     * @param request Request to the introspection endpoint
     */
    protected void secureRequest(IntrospectionRequestContext requestContext, MutableHttpRequest<?> request) {
        List<AuthenticationMethod> authMethodsSupported = requestContext.getEndpoint().getSupportedAuthenticationMethods().orElseGet(() ->
                Collections.singletonList(AuthenticationMethod.CLIENT_SECRET_BASIC));

        OauthClientConfiguration clientConfiguration = requestContext.getClientConfiguration();
        if (LOG.isTraceEnabled()) {
            LOG.trace("The introspection endpoint supports [{}] authentication methods", authMethodsSupported);
        }

        if (authMethodsSupported.contains(AuthenticationMethod.CLIENT_SECRET_BASIC)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_basic authentication. Adding an Authorization header");
            }
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        }
    }

    /**
     * Retrieves a client for the given provider.
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the request
     */
    protected RxHttpClient getClient(String providerName) {
        return introspectionClients.computeIfAbsent(providerName, (provider) -> {
            Optional<RxHttpClient> client = beanContext.findBean(RxHttpClient.class, Qualifiers.byName(provider));
            return client.orElse(defaultIntrospectionClient);
        });
    }
}
