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
package io.micronaut.security.oauth2.endpoint.userinfo;

import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.naming.Named;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.Closeable;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * {@link TokenValidator} which uses a remote `UserInfo` endpoint to validate a token.
 * <p>
 * The endpoint may be resolved lazily: if the supplier throws (for example because the OpenID provider metadata is not
 * available yet) the token is not validated by this validator and the resolution is retried on the next validation.
 * </p>
 */
@Internal
final class UserInfoClientTokenValidator implements Closeable, TokenValidator<HttpRequest<?>>, Named {
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientTokenValidator.class);
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private final String name;
    private final Supplier<Optional<Endpoint>> endpointSupplier;
    private volatile boolean resolved;
    @Nullable
    private Endpoint endpoint;

    /**
     * @param name The name qualifier
     * @param endpoint The already resolved UserInfo endpoint
     */
    UserInfoClientTokenValidator(String name, @NonNull Endpoint endpoint) {
        this.name = name;
        this.endpointSupplier = () -> Optional.of(endpoint);
        this.endpoint = endpoint;
        this.resolved = true;
    }

    /**
     * @param name The name qualifier
     * @param endpointSupplier Supplies the UserInfo endpoint. An empty optional means the provider exposes no UserInfo endpoint and is cached; an exception is not cached and the supplier is invoked again on the next validation.
     */
    UserInfoClientTokenValidator(String name, @NonNull Supplier<Optional<Endpoint>> endpointSupplier) {
        this.name = name;
        this.endpointSupplier = endpointSupplier;
    }

    @Override
    public @NonNull String getName() {
        return name;
    }

    @Override
    public void close() {
        if (resolved && endpoint != null) {
            endpoint.httpClient().close();
        }
    }

    @Override
    @NonNull
    public Publisher<Authentication> validateToken(@NonNull String token, @Nullable HttpRequest<?> request) {
        Endpoint resolvedEndpoint;
        try {
            resolvedEndpoint = endpoint().orElse(null);
        } catch (RuntimeException e) {
            // the OpenID provider metadata fetcher logs the underlying failure at ERROR, rate-limited by its back-off
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token not validated. UserInfo endpoint for client {} could not be resolved: {}", getName(), e.getMessage());
            }
            return Mono.empty();
        }
        if (resolvedEndpoint == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Token not validated. UserInfo endpoint not set for client {}", getName());
            }
            return Mono.empty();
        }
        return Mono.from(resolvedEndpoint.httpClient().retrieve(HttpRequest.GET(resolvedEndpoint.path()).bearerAuth(token),
                MAP_ARGUMENT))
            .flatMap(m -> {
                Authentication authentication = createAuthentication(m);
                return authentication == null ? Mono.empty() : Mono.just(authentication);
            })
            .onErrorResume(t -> {
                if (t instanceof HttpClientResponseException ex) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Token not validated. UserInfo endpoint for client {} responded with HTTP status code {} while validating the token", getName(), ex.getStatus().getCode());
                    }
                }
                if (LOG.isTraceEnabled()) {
                    LOG.trace(t.getMessage(), t);
                }
                return Mono.empty();
            });
    }

    @NonNull
    private Optional<Endpoint> endpoint() {
        if (!resolved) {
            synchronized (this) {
                if (!resolved) {
                    endpoint = endpointSupplier.get().orElse(null);
                    resolved = true;
                }
            }
        }
        return Optional.ofNullable(endpoint);
    }

    @Nullable
    private static Authentication createAuthentication(@NonNull Map<String, Object> claims) {
        Object subject = claims.get(Claims.SUBJECT);
        if (subject == null) {
            return null;
        }
        return Authentication.build(subject.toString(), claims);
    }

    @Override
    public int getOrder() {
        return LOWEST_PRECEDENCE - 100;
    }

    /**
     * A resolved UserInfo endpoint.
     * @param httpClient HTTP client pointed to the authorization server base URL
     * @param path UserInfo endpoint path
     */
    record Endpoint(@NonNull HttpClient httpClient, @NonNull String path) {
    }
}
