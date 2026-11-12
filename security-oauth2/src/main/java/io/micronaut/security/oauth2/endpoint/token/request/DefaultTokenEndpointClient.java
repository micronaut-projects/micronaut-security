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
import io.micronaut.http.client.LoadBalancerResolver;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.ClientAssertionConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.TokenEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethods;
import io.micronaut.security.oauth2.endpoint.token.request.context.TokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.grants.SecureGrant;
import io.micronaut.security.utils.NoRedirectHttpClientConfiguration;
import jakarta.annotation.PreDestroy;
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
 * <p>The HTTP clients this class creates never follow redirects. The default client copies the settings of the
 * {@link HttpClientConfiguration}. If an {@link HttpClientConfiguration} bean named after the provider exists
 * ({@code micronaut.http.services.<provider>.*}), or an {@link HttpClient} bean named after the provider is declared,
 * a client is created from that configuration (or from the default configuration when only the client bean exists) with
 * the load balancer of the service. The named {@link HttpClient} bean itself is not used, because its redirect policy
 * cannot be enforced.</p>
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
    private final @Nullable HttpClientConfiguration defaultClientConfiguration;
    private final ConcurrentHashMap<String, HttpClient> tokenClients = new ConcurrentHashMap<>();
    private final Set<HttpClient> createdClients = ConcurrentHashMap.newKeySet();
    private final boolean ownsDefaultClient;

    /**
     * @param beanContext The bean context
     * @param defaultClientConfiguration The default client configuration. Its settings are copied, but the client created
     *                                   from it never follows redirects.
     */
    public DefaultTokenEndpointClient(@NonNull BeanContext beanContext,
                                      HttpClientConfiguration defaultClientConfiguration) {
        this(beanContext, defaultClientConfiguration, Optional.empty());
    }

    /**
     * @param beanContext Bean Context
     * @param defaultTokenClientSupplier Default Token Client Supplier. The caller is responsible for configuring the client so that it does not follow redirects.
     */
    public DefaultTokenEndpointClient(@Nullable BeanContext beanContext,
                                      Supplier<HttpClient> defaultTokenClientSupplier) {
        this(beanContext, defaultTokenClientSupplier, null, false, Optional.empty());
    }

    private DefaultTokenEndpointClient(@Nullable BeanContext beanContext,
                                       Supplier<HttpClient> defaultTokenClientSupplier,
                                       @Nullable HttpClientConfiguration defaultClientConfiguration,
                                       boolean ownsDefaultClient,
                                       Optional<ClientAssertionGenerator> clientAssertionGenerator) {
        this.beanContext = beanContext;
        this.defaultTokenClient = SupplierUtil.memoized(defaultTokenClientSupplier);
        this.defaultClientConfiguration = defaultClientConfiguration;
        this.ownsDefaultClient = ownsDefaultClient;
        this.clientAssertionGenerator = clientAssertionGenerator;
    }

    /**
     * @param client HttpClient. The caller is responsible for configuring the client so that it does not follow redirects.
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
        this(beanContext, defaultTokenClientSupplier, null, false, clientAssertionGenerator);
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
        this(beanContext,
            () -> beanContext.createBean(HttpClient.class, LoadBalancer.empty(), new NoRedirectHttpClientConfiguration(defaultClientConfiguration)),
            defaultClientConfiguration,
            true,
            clientAssertionGenerator);
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
            secureRequestWithClientSecretBasic(request, clientConfiguration);
            return;
        }
        if (authMethodsSupported.contains(AuthenticationMethods.CLIENT_SECRET_POST)) {
            secureRequestWithClientSecretPost(request, clientConfiguration);
            return;
        }
        if (authMethodsSupported.contains(AuthenticationMethods.CLIENT_SECRET_JWT)) {
            secureRequestWithClientAssertion(request, requestContext, AuthenticationMethods.CLIENT_SECRET_JWT);
            return;
        }
        if (authMethodsSupported.contains(AuthenticationMethods.PRIVATE_KEY_JWT)) {
            secureRequestWithClientAssertion(request, requestContext, AuthenticationMethods.PRIVATE_KEY_JWT);
            return;
        }
        secureRequestWithClientId(request, clientConfiguration);
    }

    private <G> void secureRequestWithClientSecretBasic(MutableHttpRequest<G> request,
                                                        OauthClientConfiguration clientConfiguration) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Using client_secret_basic authentication. Adding an Authorization header");
        }
        request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
    }

    private <G> void secureRequestWithClientSecretPost(MutableHttpRequest<G> request,
                                                       OauthClientConfiguration clientConfiguration) {
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
    }

    private <G> void secureRequestWithClientId(MutableHttpRequest<G> request,
                                               OauthClientConfiguration clientConfiguration) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Unsupported or no authentication method. The client_id will be present in the body");
        }
        request.getBody()
                .filter(SecureGrant.class::isInstance)
                .map(SecureGrant.class::cast)
                .ifPresent(body -> body.setClientId(clientConfiguration.getClientId()));
    }

    private <G, R extends TokenResponse> void secureRequestWithClientAssertion(@NonNull MutableHttpRequest<G> request,
                                                                               TokenRequestContext<G, R> requestContext,
                                                                               String authenticationMethod) {
        ClientAssertionConfiguration clientAssertionConfiguration = clientAssertionConfiguration(requestContext.getClientConfiguration())
                .orElseGet(DefaultClientAssertionConfiguration::new);
        String clientAssertion = clientAssertionGenerator
                .orElseThrow(() -> new ConfigurationException("OAuth client " + requestContext.getClientConfiguration().getName() + " requires micronaut-security-jwt for " + authenticationMethod + " authentication"))
                .generate(requestContext, clientAssertionConfiguration, authenticationMethod);

        request.getBody()
                .filter(Map.class::isInstance)
                .map(Map.class::cast)
                .ifPresentOrElse(body -> {
                    @SuppressWarnings("unchecked")
                    Map<String, String> grant = body;
                    grant.put(SecureGrant.KEY_CLIENT_ID, requestContext.getClientConfiguration().getClientId());
                    grant.remove(SecureGrant.KEY_CLIENT_SECRET);
                    grant.put(KEY_CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE);
                    grant.put(KEY_CLIENT_ASSERTION, clientAssertion);
                }, () -> {
                    throw new ConfigurationException("OAuth client " + requestContext.getClientConfiguration().getName() + " requires a token request body map for " + authenticationMethod + " authentication");
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
     * Retrieves a client for the given provider. The returned client never follows redirects.
     *
     * <p>If an {@link HttpClientConfiguration} bean named after the provider exists, or an {@link HttpClient} bean named
     * after the provider is declared, a client is created from the named configuration (or from the default configuration
     * when only the client bean exists) with the load balancer of the service. Otherwise, the default client is returned.</p>
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the request
     */
    protected HttpClient getClient(String providerName) {
        return tokenClients.computeIfAbsent(providerName, provider -> {
            if (beanContext == null) {
                return defaultClient();
            }
            Optional<HttpClientConfiguration> namedConfiguration = beanContext.findBean(HttpClientConfiguration.class, Qualifiers.byName(provider));
            boolean namedClient = beanContext.containsBean(HttpClient.class, Qualifiers.byName(provider));
            if (namedConfiguration.isEmpty() && !namedClient) {
                return defaultClient();
            }
            if (namedClient && LOG.isWarnEnabled()) {
                LOG.warn("The HttpClient bean named [{}] is not used to call the token endpoint of provider [{}]. A client which never follows redirects is created from the {} configuration instead",
                    provider, provider, namedConfiguration.isPresent() ? "named service" : "default client");
            }
            HttpClientConfiguration configuration = namedConfiguration.orElseGet(this::defaultConfiguration);
            HttpClient client = beanContext.createBean(HttpClient.class, serviceLoadBalancer(provider), new NoRedirectHttpClientConfiguration(configuration));
            createdClients.add(client);
            return client;
        });
    }

    @NonNull
    private HttpClient defaultClient() {
        HttpClient client = defaultTokenClient.get();
        if (ownsDefaultClient) {
            createdClients.add(client);
        }
        return client;
    }

    /**
     * Closes the HTTP clients this bean created. A client supplied by the caller is not closed.
     *
     * @since 5.5.2
     */
    @PreDestroy
    public void close() {
        for (HttpClient client : createdClients) {
            client.close();
        }
        createdClients.clear();
        tokenClients.clear();
    }

    @NonNull
    private HttpClientConfiguration defaultConfiguration() {
        if (defaultClientConfiguration != null) {
            return defaultClientConfiguration;
        }
        return beanContext.getBean(HttpClientConfiguration.class);
    }

    /**
     * Resolves the load balancer of the named service, so that a relative token endpoint url is resolved against
     * {@code micronaut.http.services.<name>.url} as a client named after the provider would.
     */
    @NonNull
    private LoadBalancer serviceLoadBalancer(@NonNull String provider) {
        return beanContext.findBean(LoadBalancerResolver.class)
            .flatMap(resolver -> resolver.resolve(provider))
            .map(LoadBalancer.class::cast)
            .orElseGet(LoadBalancer::empty);
    }

    private static final class DefaultClientAssertionConfiguration implements ClientAssertionConfiguration {

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
