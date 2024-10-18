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
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Resolves a CSRF token from a request HTTP Header named {@link CsrfConfiguration#getHeaderName()}.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(property = "micronaut.security.csrf.token-resolvers.http-header.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
@Internal
final class HttpHeaderCsrfTokenResolver implements CsrfTokenResolver<HttpRequest<?>> {
    private final CsrfConfiguration csrfConfiguration;
    private final  int ORDER = -100;

    HttpHeaderCsrfTokenResolver(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    public Optional<String> resolveToken(HttpRequest<?> request) {
        String csrfToken = request.getHeaders().get(csrfConfiguration.getHeaderName());
        if (csrfToken != null) {
            return Optional.of(csrfToken);
        }
        csrfToken = request.getHeaders().get(csrfConfiguration.getHeaderName().toLowerCase());
        if (csrfToken != null) {
            return Optional.of(csrfToken);
        }
        return Optional.empty();
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
