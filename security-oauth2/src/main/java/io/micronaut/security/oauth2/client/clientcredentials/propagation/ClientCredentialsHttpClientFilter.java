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
package io.micronaut.security.oauth2.client.clientcredentials.propagation;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.BeanContext;
import io.micronaut.context.exceptions.NoSuchBeanException;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.ClientFilterChain;
import io.micronaut.http.filter.HttpClientFilter;
import io.micronaut.http.util.OutgoingHttpRequestProcessor;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsClient;
import io.micronaut.security.oauth2.client.clientcredentials.ClientCredentialsConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * An {@link HttpClientFilter} to add an access token to outgoing request thanks to a  Client Credentials request.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Filter(Filter.MATCH_ALL_PATTERN)
public class ClientCredentialsHttpClientFilter implements HttpClientFilter {
    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsHttpClientFilter.class);
    protected final OutgoingHttpRequestProcessor outgoingHttpRequestProcessor;
    protected final Collection<OauthClientConfiguration> oauthClientConfigurationCollection;
    protected final BeanContext beanContext;
    protected final Map<String, ClientCredentialsClient> clientCredentialsClientsByName = new ConcurrentHashMap<>();
    protected final Map<String, ClientCredentialsTokenPropagator> clientCredentialsTokenPropagatorByName = new ConcurrentHashMap<>();

    /**
     * @param outgoingHttpRequestProcessor Utility to decide whether to process the request
     * @param oauthClientConfigurationCollection OAuth 2.0 Clients configuration
     * @param beanContext Bean Context
     */
    public ClientCredentialsHttpClientFilter(OutgoingHttpRequestProcessor outgoingHttpRequestProcessor,
                                             Collection<OauthClientConfiguration> oauthClientConfigurationCollection,
                                             BeanContext beanContext) {
        this.outgoingHttpRequestProcessor = outgoingHttpRequestProcessor;
        this.oauthClientConfigurationCollection = oauthClientConfigurationCollection;
        this.beanContext = beanContext;
    }

    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpRequest<?> request, ClientFilterChain chain) {
        Optional<OauthClientConfiguration> oauthClientOptional = findOauthClientToDoAClientCredentialsRequest(request);
        if (!oauthClientOptional.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("did not find any OAuth 2.0 client which should decorate the request with an access token received from client credentials request");
            }
            return chain.proceed(request);
        }
        OauthClientConfiguration oauthClient = oauthClientOptional.get();
        Optional<ClientCredentialsClient> clientCredentialsClientOptional = getClientCredentialsClient(oauthClient);
        if (!clientCredentialsClientOptional.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("could not retrieve client credentials client for OAuth 2.0 client {}", oauthClient.getName());
            }
            return chain.proceed(request);
        }
        Optional<ClientCredentialsTokenPropagator> clientCredentialsClientTokenPropagatorOptional = getClientCredentialsTokenPropagator(oauthClient);
        if (!clientCredentialsClientTokenPropagatorOptional.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("could not retrieve client credentials token propagator for OAuth 2.0 client {}", oauthClient.getName());
            }
            return chain.proceed(request);
        }
        return Flowable.fromPublisher(clientCredentialsClientOptional.get()
                .clientCredentials(getScope(oauthClient)))
                .map(TokenResponse::getAccessToken)
                .switchMap(accessToken -> {
            if (StringUtils.isNotEmpty(accessToken)) {
                clientCredentialsClientTokenPropagatorOptional.get().writeToken(request, accessToken);
            }
            return chain.proceed(request);
        });
    }

    /**
     *
     * @param oauthClient OAuth 2.0 Client configuration
     * @return The desired scope for client credentials grant or null if no scope should be specified
     */
    @Nullable
    protected String getScope(@NonNull OauthClientConfiguration oauthClient) {
        return oauthClient.getClientCredentials().isPresent() ? oauthClient.getClientCredentials().get().getScope() : null;
    }

    /**
     *
     * @param oauthClient OAuth 2.0 Client configuration
     * @return The Client credentials client for the OAuth 2.0 Client.
     */
    protected Optional<ClientCredentialsClient> getClientCredentialsClient(@NonNull OauthClientConfiguration oauthClient) {
        try {
            Function<String, ClientCredentialsClient> mappingFunction = key ->
                    beanContext.getBean(ClientCredentialsClient.class, Qualifiers.byName(oauthClient.getName()));
            return Optional.of(clientCredentialsClientsByName.computeIfAbsent(oauthClient.getName(), mappingFunction));
        } catch (NoSuchBeanException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("no client credentials client for OAuth 2.0 client {}", oauthClient.getName());
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param oauthClient OAuth 2.0 Client configuration
     * @return The Client credentials token propagator for the OAuth 2.0 Client.
     */
    protected Optional<ClientCredentialsTokenPropagator> getClientCredentialsTokenPropagator(@NonNull OauthClientConfiguration oauthClient) {
        try {
            Function<String, ClientCredentialsTokenPropagator> mappingFunction = key ->
                    beanContext.getBean(ClientCredentialsTokenPropagator.class, Qualifiers.byName(oauthClient.getName()));
            return Optional.of(clientCredentialsTokenPropagatorByName.computeIfAbsent(oauthClient.getName(), mappingFunction));
        } catch (NoSuchBeanException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("no client credentials client token propagator for OAuth 2.0 client {}", oauthClient.getName());
            }
        }
        return Optional.empty();
    }

    /**
     *
     * @param request Http Request
     * @return An OAuth 2.0 Client configuration which has client credentials configuration set and should process the request
     */
    protected Optional<OauthClientConfiguration> findOauthClientToDoAClientCredentialsRequest(HttpRequest<?> request) {
        for (OauthClientConfiguration oauthClient : oauthClientConfigurationCollection) {
            if (oauthClient.getClientCredentials().isPresent()) {
                ClientCredentialsConfiguration clientCredentialsConfiguration = oauthClient.getClientCredentials().get();
                if (clientCredentialsConfiguration.isEnabled() &&
                        outgoingHttpRequestProcessor.shouldProcessRequest(clientCredentialsConfiguration, request)) {
                    return Optional.of(oauthClient);
                }
            }
        }
        return Optional.empty();
    }
}
