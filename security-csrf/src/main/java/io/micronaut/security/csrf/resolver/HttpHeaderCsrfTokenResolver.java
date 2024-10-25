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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Resolves a CSRF token from a request HTTP Header named {@link CsrfConfiguration#getHeaderName()}.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = CsrfConfiguration.PREFIX + ".token-resolvers.http-header.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
@Internal
final class HttpHeaderCsrfTokenResolver implements CsrfTokenResolver<HttpRequest<?>> {
    private static final int ORDER = -100;
    private final String lowerHeaderName;
    private final String headerName;

    HttpHeaderCsrfTokenResolver(CsrfConfiguration csrfConfiguration) {
        headerName = csrfConfiguration.getHeaderName();
        lowerHeaderName = headerName.toLowerCase();
    }

    @Override
    @NonNull
    public Optional<String> resolveToken(@NonNull HttpRequest<?> request) {
        final HttpHeaders httpHeaders = request.getHeaders();
        String csrfToken = httpHeaders.get(headerName);
        if (StringUtils.isNotEmpty(csrfToken)) {
            return Optional.of(csrfToken);
        }
        csrfToken = httpHeaders.get(lowerHeaderName);
        if (StringUtils.isNotEmpty(csrfToken)) {
            return Optional.of(csrfToken);
        }
        return Optional.empty();
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
