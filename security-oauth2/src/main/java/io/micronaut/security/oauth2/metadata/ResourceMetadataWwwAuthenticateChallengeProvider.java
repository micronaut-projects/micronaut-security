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
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaderValues;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.security.authentication.WwwAuthenticateChallenge;
import io.micronaut.security.authentication.WwwAuthenticateChallengeProvider;
import jakarta.inject.Singleton;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Use of WWW-Authenticate for Protected Resource Metadata.
 * <a href="https://datatracker.ietf.org/doc/html/rfc9728#WWW-Authenticate">RFC 9728 WWW Authenticate</a>
 */
@Requires(classes = { HttpRequest.class, HttpHostResolver.class })
@Requires(beans = { HttpHostResolver.class, ProtectedResourceMetadataProvider.class })
@Requires(property = ProtectedResourceMetadataConfiguration.PROPERTY_WWW_AUTHENTICATE, notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
class ResourceMetadataWwwAuthenticateChallengeProvider implements WwwAuthenticateChallengeProvider<HttpRequest<?>> {
    private static final String PARAM_RESOURCE_METADATA = "resource_metadata";
    private static final String PARAM_SCOPE = "scope";
    private static final String SLASH = "/";
    private final HttpHostResolver httpHostResolver;
    private final ProtectedResourceMetadataProvider<HttpRequest<?>> protectedResourceMetadataProvider;

    ResourceMetadataWwwAuthenticateChallengeProvider(HttpHostResolver httpHostResolver,
                                                     ProtectedResourceMetadataProvider<HttpRequest<?>> protectedResourceMetadataProvider) {
        this.httpHostResolver = httpHostResolver;
        this.protectedResourceMetadataProvider = protectedResourceMetadataProvider;
    }

    @Override
    @NonNull
    public String getWwwAuthenticateChallenge(@Nullable HttpRequest<?> request) {
        WwwAuthenticateChallenge.Builder builder = WwwAuthenticateChallenge.builder()
            .authScheme(HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER)
            .param(PARAM_RESOURCE_METADATA,  resourceMetadata(request));
        String scope = scope(request);
        if (StringUtils.isNotEmpty(scope)) {
            builder.param(PARAM_SCOPE, scope);
        }
        return builder
            .build()
            .toString();
    }

    @NonNull
    private String resourceMetadata(@Nullable HttpRequest<?> request) {
        StringBuilder sb = new StringBuilder();
        sb.append(httpHostResolver.resolve(request));
        sb.append(ProtectedResourceMetadataConfiguration.PATH);
        String path = resourcePath(request);
        if (path != null) {
            sb.append(path);
        }
        return sb.toString();
    }

    @Nullable
    private String resourcePath(@Nullable HttpRequest<?> request) {
        if (request == null) {
            return null;
        }
        String path = request.getPath();
        return StringUtils.isNotEmpty(path) && !SLASH.equals(path) ? path : null;
    }

    @NonNull
    private String scope(@Nullable HttpRequest<?> request) {
        if (request == null) {
            return "";
        }
        String path = resourcePath(request);
        ProtectedResourceMetadata metadata = path == null
            ? protectedResourceMetadataProvider.get(request)
            : protectedResourceMetadataProvider.get(path, request);
        if (metadata == null) {
            return "";
        }
        List<String> scopes = metadata.scopesSupported();
        if (scopes == null || scopes.isEmpty()) {
            return "";
        }
        return scopes.stream()
            .filter(scope -> scope != null && StringUtils.isNotEmpty(scope.trim()))
            .map(String::trim)
            .collect(Collectors.joining(" "));
    }
}
