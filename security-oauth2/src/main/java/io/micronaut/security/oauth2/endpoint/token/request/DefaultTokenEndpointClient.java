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
package io.micronaut.security.oauth2.endpoint.token.request;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.ClientAssertionConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.SecureGrant;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The default implementation of {@link TokenEndpointClient}.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(beans = HttpClientConfiguration.class)
@Singleton
public class DefaultTokenEndpointClient implements TokenEndpointClient  {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenEndpointClient.class);
    private static final String KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";
    private static final String KEY_CLIENT_ASSERTION = "client_assertion";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final @Nullable BeanContext beanContext;
    private final Supplier<HttpClient> defaultTokenClient;
    private final Optional<ClientAssertionGenerator> clientAssertionGenerator;
    private final ConcurrentHashMap<String, HttpClient> tokenClients = new ConcurrentHashMap<>();

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration
     */
    public DefaultTokenEndpointClient(@NonNull BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration) {
        this(beanContext, () -> beanContext.createBean(HttpClient.class, LoadBalancer.empty(), defaultClientConfiguration), Optional.empty());
    }

    /**
     * @param beanContext Bean Context
     * @param defaultTokenClientSupplier Default Token Client Supplier
     */
    public DefaultTokenEndpointClient(@Nullable BeanContext beanContext,
                                      Supplier<HttpClient> defaultTokenClientSupplier) {
        this(beanContext, defaultTokenClientSupplier, Optional.empty());
    }

    /**
     * @param client HttpClient
     */
    public DefaultTokenEndpointClient(HttpClient client) {
        this(null, () -> client, Optional.empty());
    }

    /**
     * @param beanContext Bean Context
     * @param defaultTokenClientSupplier Default Token Client Supplier
     * @param clientAssertionGenerator The optional client assertion generator
     */
    DefaultTokenEndpointClient(@Nullable BeanContext beanContext,
                               Supplier<HttpClient> defaultTokenClientSupplier,
                               Optional<ClientAssertionGenerator> clientAssertionGenerator) {
        this.beanContext = beanContext;
        this.clientAssertionGenerator = clientAssertionGenerator;
        this.defaultTokenClient = SupplierUtil.memoized(defaultTokenClientSupplier);
    }

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration
     * @param clientAssertionGenerator The optional client assertion generator
     */
    @Inject
    public DefaultTokenEndpointClient(BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration,
                                      Optional<ClientAssertionGenerator> clientAssertionGenerator) {
        this(beanContext, () -> beanContext.createBean(HttpClient.class, LoadBalancer.empty(), defaultClientConfiguration), clientAssertionGenerator);
    }

    @NonNull
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
    protected <G, R extends TokenResponse> void secureRequest(@NonNull MutableHttpRequest<G> request,
                                 TokenRequestContext<G, R> requestContext) {
        Set<String> authMethodsSupported = requestContext.getEndpoint().getAuthenticationMethodsSupported();
        if (authMethodsSupported == null) {
            authMethodsSupported = Collections.singleton(AuthenticationMethods.CLIENT_SECRET_BASIC);
        }

        OauthClientConfiguration clientConfiguration = requestContext.getClientConfiguration();
        if (LOG.isTraceEnabled()) {
            LOG.trace("The token endpoint supports [{}] authentication methods", authMethodsSupported);
        }

        if (authMethodsSupported.contains(AuthenticationMethods.CLIENT_SECRET_BASIC)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_basic authentication. Adding an Authorization header");
            }
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        } else if (authMethodsSupported.contains(AuthenticationMethods.CLIENT_SECRET_POST)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_post authentication. The client_id and client_secret will be present in the body");
            }
            request.getBody()
                    .filter(SecureGrant.class::isInstance)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> {
                        body.setClientId(clientConfiguration.getClientId());
                        body.setClientSecret(clientConfiguration.getClientSecret());
                    });
        } else if (authMethodsSupported.contains(AuthenticationMethods.CLIENT_SECRET_JWT)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using client_secret_jwt authentication. A signed client assertion will be present in the body");
            }
            secureRequestWithClientAssertion(request, requestContext, AuthenticationMethods.CLIENT_SECRET_JWT);
        } else if (authMethodsSupported.contains(AuthenticationMethods.PRIVATE_KEY_JWT)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Using private_key_jwt authentication. A signed client assertion will be present in the body");
            }
            secureRequestWithClientAssertion(request, requestContext, AuthenticationMethods.PRIVATE_KEY_JWT);
        } else {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Unsupported or no authentication method. The client_id will be present in the body");
            }
            request.getBody()
                    .filter(SecureGrant.class::isInstance)
                    .map(SecureGrant.class::cast)
                    .ifPresent(body -> body.setClientId(clientConfiguration.getClientId()));
        }
    }

    private <G, R extends TokenResponse> void secureRequestWithClientAssertion(@NonNull MutableHttpRequest<G> request,
                                                                               TokenRequestContext<G, R> requestContext,
                                                                               String authenticationMethod) {
        ClientAssertionConfiguration clientAssertionConfiguration = clientAssertionConfiguration(requestContext.getClientConfiguration())
                .orElse(DefaultClientAssertionConfiguration.INSTANCE);
        String clientAssertion = clientAssertionGenerator
                .orElseThrow(() -> new ConfigurationException("OAuth client " + requestContext.getClientConfiguration().getName() + " requires micronaut-security-jwt for " + authenticationMethod + " authentication"))
                .generate(requestContext, clientAssertionConfiguration, authenticationMethod);

        request.getBody()
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .ifPresentOrElse(body -> {
                    @SuppressWarnings("unchecked")
                    Map<String, String> grant = (Map<String, String>) body;
                    grant.put(SecureGrant.KEY_CLIENT_ID, requestContext.getClientConfiguration().getClientId());
                    grant.remove(SecureGrant.KEY_CLIENT_SECRET);
                    grant.put(KEY_CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE);
                    grant.put(KEY_CLIENT_ASSERTION, clientAssertion);
                }, () -> {
                    throw new ConfigurationException("OAuth client assertion authentication requires a token request body map");
                });
    }

    private Optional<ClientAssertionConfiguration> clientAssertionConfiguration(OauthClientConfiguration clientConfiguration) {
        return clientConfiguration.getOpenid()
                .flatMap(OpenIdClientConfiguration::getToken)
                .flatMap(TokenEndpointConfiguration::getClientAssertion)
                .or(() -> clientConfiguration.getToken()
                        .filter(TokenEndpointConfiguration.class::isInstance)
                        .map(TokenEndpointConfiguration.class::cast)
                        .flatMap(TokenEndpointConfiguration::getClientAssertion));
    }

    /**
     * Retrieves a client for the given provider.
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the request
     */
    protected HttpClient getClient(String providerName) {
        return tokenClients.computeIfAbsent(providerName, provider -> {
            Optional<HttpClient> client = beanContext == null ? Optional.empty() : beanContext.findBean(HttpClient.class, Qualifiers.byName(provider));
            return client.orElseGet(defaultTokenClient);
        });
    }

    private static final class DefaultClientAssertionConfiguration implements ClientAssertionConfiguration {
        private static final DefaultClientAssertionConfiguration INSTANCE = new DefaultClientAssertionConfiguration();

        @NonNull
        @Override
        public Duration getLifetime() {
            return DEFAULT_LIFETIME;
        }

        @NonNull
        @Override
        public Optional<String> getAudience() {
            return Optional.empty();
        }

        @NonNull
        @Override
        public Optional<String> getIssuer() {
            return Optional.empty();
        }

        @NonNull
        @Override
        public Optional<String> getSubject() {
            return Optional.empty();
        }

        @NonNull
        @Override
        public Optional<String> getSigningAlgorithm() {
            return Optional.empty();
        }

        @NonNull
        @Override
        public Optional<String> getSignerName() {
            return Optional.empty();
        }
    }

    /**
     * Internal strategy for generating OAuth2 token endpoint client assertions.
     *
     * @since 5.1.0
     */
    @Internal
    public interface ClientAssertionGenerator {

        /**
         * @param requestContext The token request context
         * @param clientAssertionConfiguration The client assertion configuration
         * @param authenticationMethod The selected token endpoint authentication method
         * @return The serialized client assertion
         */
        @NonNull
        String generate(@NonNull TokenRequestContext<?, ? extends TokenResponse> requestContext,
                        @NonNull ClientAssertionConfiguration clientAssertionConfiguration,
                        @NonNull String authenticationMethod);
    }
}
