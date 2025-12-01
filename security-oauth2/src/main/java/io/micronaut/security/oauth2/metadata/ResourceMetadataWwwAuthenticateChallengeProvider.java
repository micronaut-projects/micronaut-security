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

/**
 * Use of WWW-Authenticate for Protected Resource Metadata.
 * <a href="https://datatracker.ietf.org/doc/html/rfc9728#WWW-Authenticate">RFC 9728 WWW Authenticate</a>
 */
@Requires(classes = HttpRequest.class)
@Requires(property = ProtectedResourceMetadataConfiguration.PROPERTY_WWW_AUTHENTICATE, notEquals = StringUtils.FALSE, defaultValue = StringUtils.TRUE)
@Internal
@Singleton
class ResourceMetadataWwwAuthenticateChallengeProvider implements WwwAuthenticateChallengeProvider<HttpRequest<?>> {
    private static final String PARAM_RESOURCE_METADATA = "resource_metadata";
    private static final String SLASH = "/";
    private final HttpHostResolver  httpHostResolver;

    ResourceMetadataWwwAuthenticateChallengeProvider(HttpHostResolver httpHostResolver) {
        this.httpHostResolver = httpHostResolver;
    }

    @Override
    @NonNull
    public String getWwwAuthenticateChallenge(@Nullable HttpRequest<?> request) {
        return WwwAuthenticateChallenge.builder()
            .authScheme(HttpHeaderValues.AUTHORIZATION_PREFIX_BEARER)
            .param(PARAM_RESOURCE_METADATA,  resourceMetadata(request))
            .build()
            .toString();
    }

    @NonNull
    private String resourceMetadata(@Nullable HttpRequest<?> request) {
        StringBuilder sb = new StringBuilder();
        sb.append(httpHostResolver.resolve(request));
        sb.append(ProtectedResourceMetadataConfiguration.PATH);
        if (request != null && StringUtils.isNotEmpty(request.getPath()) && !request.getPath().equals(SLASH)) {
            sb.append(request.getPath());
        }
        return sb.toString();
    }
}
