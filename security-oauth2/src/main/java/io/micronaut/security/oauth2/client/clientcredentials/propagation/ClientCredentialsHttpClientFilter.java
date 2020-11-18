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

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    protected final List<OauthClientConfiguration> oauthClientConfigurationCollection;
    protected final BeanContext beanContext;
    protected final Map<String, ClientCredentialsClient> clientCredentialsClientsByName = new ConcurrentHashMap<>();
    protected final Map<String, ClientCredentialsTokenPropagator> clientCredentialsTokenHandlerByName = new ConcurrentHashMap<>();
    private final Function<String, ClientCredentialsClient> clientFunction;
    private final Function<String, ClientCredentialsTokenPropagator> tokenPropagatorFunction;

    /**
     * @param outgoingHttpRequestProcessor Utility to decide whether to process the request
     * @param oauthClientConfigurationStream OAuth 2.0 Clients configuration stream
     * @param defaultTokenPropagator The default token propagator
     * @param beanContext Bean Context
     */
    public ClientCredentialsHttpClientFilter(OutgoingHttpRequestProcessor outgoingHttpRequestProcessor,
                                             Stream<OauthClientConfiguration> oauthClientConfigurationStream,
                                             ClientCredentialsTokenPropagator defaultTokenPropagator,
                                             BeanContext beanContext) {
        this.outgoingHttpRequestProcessor = outgoingHttpRequestProcessor;
        this.oauthClientConfigurationCollection = oauthClientConfigurationStream
                .filter(config -> config.getClientCredentials().map(ClientCredentialsConfiguration::isEnabled).orElse(false))
                .collect(Collectors.toList());
        this.beanContext = beanContext;
        this.clientFunction = key -> beanContext.getBean(ClientCredentialsClient.class, Qualifiers.byName(key));
        this.tokenPropagatorFunction = key ->
                beanContext.findBean(ClientCredentialsTokenPropagator.class, Qualifiers.byName(key))
                        .orElse(defaultTokenPropagator);
    }

    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpRequest<?> request, ClientFilterChain chain) {
        Optional<OauthClientConfiguration> oauthClientOptional = getClientConfiguration(request);
        if (!oauthClientOptional.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Did not find any OAuth 2.0 client which should decorate the request with an access token received from client credentials request");
            }
            return chain.proceed(request);
        }
        OauthClientConfiguration oauthClient = oauthClientOptional.get();
        Optional<ClientCredentialsClient> clientCredentialsClientOptional = getClient(oauthClient);
        if (!clientCredentialsClientOptional.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Could not retrieve client credentials client for OAuth 2.0 client {}", oauthClient.getName());
            }
            return chain.proceed(request);
        }
        ClientCredentialsTokenPropagator tokenHandler = getTokenHandler(oauthClient);

        return Flowable.fromPublisher(clientCredentialsClientOptional.get()
                .requestToken(getScope(oauthClient)))
                .map(TokenResponse::getAccessToken)
                .switchMap(accessToken -> {
            if (StringUtils.isNotEmpty(accessToken)) {
                tokenHandler.writeToken(request, accessToken);
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
        return oauthClient.getClientCredentials().flatMap(ClientCredentialsConfiguration::getScope).orElse(null);
    }

    /**
     *
     * @param oauthClient OAuth 2.0 Client configuration
     * @return The Client credentials client for the OAuth 2.0 Client.
     */
    protected Optional<ClientCredentialsClient> getClient(@NonNull OauthClientConfiguration oauthClient) {
        try {
            return Optional.of(clientCredentialsClientsByName.computeIfAbsent(oauthClient.getName(), clientFunction));
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
    protected ClientCredentialsTokenPropagator getTokenHandler(@NonNull OauthClientConfiguration oauthClient) {
        return clientCredentialsTokenHandlerByName.computeIfAbsent(oauthClient.getName(), tokenPropagatorFunction);
    }

    /**
     *
     * @param request Http Request
     * @return An OAuth 2.0 Client configuration which has client credentials configuration set and should process the request
     */
    protected Optional<OauthClientConfiguration> getClientConfiguration(HttpRequest<?> request) {
        for (OauthClientConfiguration oauthClient : oauthClientConfigurationCollection) {
            ClientCredentialsConfiguration clientCredentialsConfiguration = oauthClient.getClientCredentials().get();
            if (outgoingHttpRequestProcessor.shouldProcessRequest(clientCredentialsConfiguration, request)) {
                return Optional.of(oauthClient);
            }
        }
        return Optional.empty();
    }
}
