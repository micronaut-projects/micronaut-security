/*
 * Copyright 2017-2025 original authors
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
package io.micronaut.security.oauth2.metadata;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Experimental;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.runtime.ApplicationConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdClientConfiguration;
import jakarta.inject.Singleton;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Default implementation of {@link ProtectedResourceMetadataProvider}.
 */
@Requires(classes = HttpRequest.class)
@Experimental
@Singleton
public class DefaultProtectedResourceMetadataProvider implements ProtectedResourceMetadataProvider<HttpRequest<?>> {
    /**
     * Application configuration.
     */
    protected final ApplicationConfiguration applicationConfiguration;
    /**
     * HTTP Host Resolver.
     */
    protected final HttpHostResolver httpHostResolver;

    /**
     * OpenID client configurations.
     */
    protected final List<OpenIdClientConfiguration> openIdClients;

    /**
     *
     * @param applicationConfiguration Application configuration.
     * @param httpHostResolver HTTP Host Resolver.
     * @param openIdClients OpenID client configurations.
     */
    public DefaultProtectedResourceMetadataProvider(ApplicationConfiguration applicationConfiguration,
                                                    HttpHostResolver httpHostResolver,
                                                    List<OpenIdClientConfiguration> openIdClients) {
        this.applicationConfiguration = applicationConfiguration;
        this.httpHostResolver = httpHostResolver;
        this.openIdClients = openIdClients;
    }

    @Override
    @NonNull
    public ProtectedResourceMetadata get(@NonNull HttpRequest<?> request) {
        return builder(null, request).build();
    }

    @Override
    @NonNull
    public ProtectedResourceMetadata get(@NonNull String path, @NonNull HttpRequest<?> request) {
        return builder(path, request).build();
    }

    /**
     * Creates a Protected Resource Metadata builder.
     * @param path Path component
     * @param request The HTTP Request
     * @return a Protected Resource Metadata builder
     */
    @NonNull
    protected ProtectedResourceMetadata.Builder builder(@Nullable String path, @NonNull HttpRequest<?> request) {
        ProtectedResourceMetadata.Builder builder = ProtectedResourceMetadata.builder()
            .resource(resource(path, request));
        List<String> authorizationServers = authorizationServers(path, request);
        if (CollectionUtils.isNotEmpty(authorizationServers)) {
            builder.authorizationServers(authorizationServers);
        }
        applicationConfiguration.getName().ifPresent(builder::resourceName);
        return builder;
    }

    /**
     *
     * @param path The Path component
     * @param request the Request
     * @return the Resource
     */
    @NonNull
    protected String resource(@Nullable String path, @NonNull HttpRequest<?> request) {
        String host = httpHostResolver.resolve(request);
        return StringUtils.isNotEmpty(path)
            ? host + path
            : host;
    }

    /**
     * Authorization Servers for the Protected Resource Metadata.
     * @param path Path component
     * @param request HTTP Requests
     * @return Authorization Servers
     */
    @NonNull
    protected List<String> authorizationServers(@Nullable String path, @NonNull HttpRequest<?> request) {
        List<String> result = new ArrayList<>(openIdClients.size());
        for (OpenIdClientConfiguration openIdClientConfiguration : openIdClients) {
            if (openIdClientConfiguration.isProtectedResourceMetadata()) {
                openIdClientConfiguration.getIssuer().map(URL::toString).ifPresent(result::add);
            }
        }
        return result;
    }
}
