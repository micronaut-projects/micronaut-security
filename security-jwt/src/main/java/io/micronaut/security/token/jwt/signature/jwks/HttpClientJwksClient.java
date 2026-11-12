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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.HttpClientRegistry;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.LoadBalancerResolver;
import io.micronaut.http.client.ServiceHttpClientConfiguration;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.http.client.exceptions.ReadTimeoutException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import io.micronaut.security.utils.NoRedirectHttpClientConfiguration;
import jakarta.annotation.PreDestroy;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Implementation of {@link JwksClient} that uses the Micronaut {@link HttpClient}.
 *
 * <p>
 * If a named service-specific client is configured (i.e. with "micronaut.http.services.foo.*") with a
 * name that matches the name used for security configuration (i.e. "micronaut.security.token.jwt.signatures.jwks.foo.*")
 * then that client will be used for the request. Otherwise, a default client will be used.
 *
 * </p>
 * <p>
 * Neither the default client nor a named service-specific client follows redirects: the settings of the
 * service configuration are copied but {@code micronaut.http.services.foo.follow-redirects} is ignored.
 * </p>
 *  @author Jeremy Grelle
 *  @since 4.5.0
 */
@Singleton
@Requires(beans = HttpClientRegistry.class)
@Requires(property = JwtConfigurationProperties.PREFIX + ".signatures.jwks-client.http-client.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
public class HttpClientJwksClient implements JwksClient {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClientJwksClient.class);

    private final BeanContext beanContext;
    private final HttpClientRegistry<HttpClient> clientRegistry;
    private final Supplier<HttpClient> defaultJwkSetClient;
    private final ConcurrentHashMap<String, HttpClient> jwkSetClients = new ConcurrentHashMap<>();
    private final Set<HttpClient> createdClients = ConcurrentHashMap.newKeySet();

    /**
     *
     * @param beanContext BeanContext
     * @param clientRegistry HTTP Client Registry
     * @param defaultClientConfiguration Default HTTP Client Configuration. Its settings are copied, but the client created from it never follows redirects.
     */
    public HttpClientJwksClient(BeanContext beanContext, HttpClientRegistry<HttpClient> clientRegistry, HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.clientRegistry = clientRegistry;
        this.defaultJwkSetClient = SupplierUtil.memoized(() -> track(beanContext.createBean(HttpClient.class, LoadBalancer.empty(), new NoRedirectHttpClientConfiguration(defaultClientConfiguration))));
    }

    @Override
    @SingleResult
    public Publisher<String> load(@Nullable String providerName, @NonNull String url) throws HttpClientException {
        return Mono.deferContextual(ctx -> Mono.from(getClient(providerName).retrieve(url))
            .onErrorResume(HttpClientException.class, throwable -> {
                if (throwable instanceof ReadTimeoutException && alreadyVerified(ctx)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Read timeout loading JWK from {} (ignored because token already verified)", url, throwable);
                    }
                } else if (LOG.isErrorEnabled()) {
                    LOG.error("Exception loading JWK from " + url, throwable);
                }
                return Mono.empty();
            }));
    }

    private static boolean alreadyVerified(ContextView ctx) {
        if (ctx != null && ctx.hasKey(JwksClientReactorContext.class)) {
            JwksClientReactorContext reactorContext = ctx.get(JwksClientReactorContext.class);
            return reactorContext.isTokenVerified();
        }
        return false;
    }

    /**
     * Retrieves an HTTP client for the given provider.
     *
     * @param providerName The provider name
     * @return An HTTP client to use to send the JWKS request
     */
    protected HttpClient getClient(@Nullable String providerName) {
        if (providerName == null) {
            return defaultJwkSetClient.get();
        }
        return jwkSetClients.computeIfAbsent(providerName, provider ->
            beanContext.findBean(ServiceHttpClientConfiguration.class, Qualifiers.byName(provider))
                .map(serviceConfig -> track(beanContext.createBean(HttpClient.class, serviceLoadBalancer(provider), new NoRedirectHttpClientConfiguration(serviceConfig))))
                .orElseGet(defaultJwkSetClient));
    }

    /**
     * Resolves the load balancer of the named service, so that a relative JWKS url is resolved against
     * {@code micronaut.http.services.<name>.url} as it was when the registry client was used.
     */
    @NonNull
    private LoadBalancer serviceLoadBalancer(@NonNull String provider) {
        return beanContext.findBean(LoadBalancerResolver.class)
            .flatMap(resolver -> resolver.resolve(provider))
            .map(LoadBalancer.class::cast)
            .orElseGet(LoadBalancer::empty);
    }

    private HttpClient track(HttpClient client) {
        createdClients.add(client);
        return client;
    }

    /**
     * Closes the HTTP clients this bean created.
     *
     * @since 5.5.2
     */
    @PreDestroy
    public void close() {
        for (HttpClient client : createdClients) {
            client.close();
        }
        createdClients.clear();
        jwkSetClients.clear();
    }
}
