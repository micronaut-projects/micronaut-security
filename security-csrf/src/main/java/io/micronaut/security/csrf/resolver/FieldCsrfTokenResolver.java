/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.resolver;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.ServerHttpRequest;
import io.micronaut.http.server.filter.FilterBodyParser;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;
import java.util.concurrent.CompletableFuture;

/**
 * Resolves a CSRF token from a form-urlencoded body using the {@link ServerHttpRequest#byteBody()} API.
 *
 * @since 2.0.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = CsrfConfiguration.PREFIX + ".token-resolvers.field.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
final class FieldCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
    private final CsrfConfiguration csrfConfiguration;
    private final FilterBodyParser filterBodyParser;

    /**
     *
     * @param csrfConfiguration CSRF Configuration
     * @param filterBodyParser Filter Body Parser
     */
    FieldCsrfTokenResolver(CsrfConfiguration csrfConfiguration, FilterBodyParser filterBodyParser) {
        this.csrfConfiguration = csrfConfiguration;
        this.filterBodyParser = filterBodyParser;
    }

    @Override
    @NonNull
    public CompletableFuture<String> resolveToken(@NonNull HttpRequest<?> request) {
        if (request instanceof ServerHttpRequest<?> serverHttpRequest) {
            return resolveToken(serverHttpRequest);
        }
        return CompletableFuture.completedFuture(null);
    }

    private CompletableFuture<String> resolveToken(ServerHttpRequest<?> request) {
        return filterBodyParser.parseBody(request)
                .thenApply(m -> {
                    Object csrfToken = m.get(csrfConfiguration.getFieldName());
                    return csrfToken == null || StringUtils.isEmpty(csrfToken.toString())
                            ? null
                            : csrfToken.toString();
                });
    }
}
