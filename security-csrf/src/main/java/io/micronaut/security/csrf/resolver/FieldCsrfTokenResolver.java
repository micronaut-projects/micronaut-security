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
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.ServerHttpRequest;
import io.micronaut.http.exceptions.ContentLengthExceededException;
import io.micronaut.http.server.filter.FilterBodyParser;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Resolves a CSRF token from a form-urlencoded body using the {@link ServerHttpRequest#byteBody()} API.
 * If the body cannot be parsed, for example because it contains an invalid percent escape, no token is resolved
 * and the request is rejected by the {@code CsrfFilter} like any other request without a CSRF token.
 * A body exceeding the maximum request size is not swallowed: the {@link ContentLengthExceededException} is propagated.
 * The raw body is never logged.
 *
 * @since 2.0.0
 */
@Requires(classes = HttpRequest.class)
@Requires(property = CsrfConfiguration.PREFIX + ".token-resolvers.field.enabled", value = StringUtils.TRUE, defaultValue = StringUtils.TRUE)
@Singleton
final class FieldCsrfTokenResolver implements FutureCsrfTokenResolver<HttpRequest<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(FieldCsrfTokenResolver.class);
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
        CompletableFuture<Map<String, Object>> body;
        try {
            body = filterBodyParser.parseBody(request);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(bodyNotParsed(e));
        }
        return body.handle((m, throwable) -> {
            if (throwable != null) {
                return bodyNotParsed(throwable);
            }
            Object csrfToken = m.get(csrfConfiguration.getFieldName());
            return csrfToken == null || StringUtils.isEmpty(csrfToken.toString())
                    ? null
                    : csrfToken.toString();
        });
    }

    /**
     * The exception message of a body parsing failure may contain the raw request body, so only the exception type is logged.
     * @param throwable Body parsing failure
     * @throws ContentLengthExceededException if the body exceeds the maximum request size
     * @return {@code null}, no CSRF token could be resolved
     */
    @Nullable
    private static String bodyNotParsed(@NonNull Throwable throwable) {
        Throwable cause = throwable instanceof CompletionException && throwable.getCause() != null ? throwable.getCause() : throwable;
        if (cause instanceof ContentLengthExceededException contentLengthExceededException) {
            // never contains the body; rethrown so that the client gets 413 instead of 401
            throw contentLengthExceededException;
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Could not parse the request body to resolve the CSRF token: {}", cause.getClass().getName());
        }
        return null;
    }
}
