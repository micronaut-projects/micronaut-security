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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.util.StringUtils;
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.HttpClientConfiguration;
import io.micronaut.http.client.HttpClientRegistry;
import io.micronaut.http.client.HttpVersionSelection;
import io.micronaut.http.client.LoadBalancer;
import io.micronaut.http.client.ServiceHttpClientConfiguration;
import io.micronaut.http.client.exceptions.HttpClientException;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.security.token.jwt.config.JwtConfigurationProperties;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
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
 *  @author Jeremy Grelle
 *  @since 4.5.0
 */
@Singleton
@Requires(classes = HttpClient.class)
@Requires(property = JwtConfigurationProperties.PREFIX + ".signatures.jwks-client.http-client.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
public class HttpClientJwksClient implements JwksClient {

    private static final Logger LOG = LoggerFactory.getLogger(HttpClientJwksClient.class);

    private final BeanContext beanContext;
    private final HttpClientRegistry<HttpClient> clientRegistry;
    private final Supplier<HttpClient> defaultJwkSetClient;
    private final ConcurrentHashMap<String, HttpClient> jwkSetClients = new ConcurrentHashMap<>();

    /**
     *
     * @param beanContext BeanContext
     * @param clientRegistry HTTP Client Registry
     * @param defaultClientConfiguration Default HTTP Client Configuration
     */
    public HttpClientJwksClient(BeanContext beanContext, HttpClientRegistry<HttpClient> clientRegistry, HttpClientConfiguration defaultClientConfiguration) {
        this.beanContext = beanContext;
        this.clientRegistry = clientRegistry;
        this.defaultJwkSetClient = SupplierUtil.memoized(() -> beanContext.createBean(HttpClient.class, LoadBalancer.empty(), defaultClientConfiguration));
    }

    @Override
    @SingleResult
    public Publisher<String> load(@Nullable String providerName, @NonNull String url) throws HttpClientException {
        return Mono.from(getClient(providerName)
                .retrieve(url))
                .onErrorResume(HttpClientException.class, throwable -> {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("Exception loading JWK from " + url, throwable);
                    }
                    return Mono.empty();
                });
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
                .map(serviceConfig -> this.clientRegistry.getClient(HttpVersionSelection.forClientConfiguration(serviceConfig), provider, "/"))
                .orElseGet(defaultJwkSetClient));
    }
}
