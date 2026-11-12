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

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.naming.Named;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.endpoint.token.response.OauthAuthenticationMapper;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.validator.TokenValidator;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.io.Closeable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * {@link TokenValidator} which uses a remote `UserInfo` endpoint to validate a token.
 * <p>
 * The {@link Authentication} built from the UserInfo response is bound to the provider which answered. The attribute
 * {@link OauthAuthenticationMapper#PROVIDER_KEY} is always set to the provider name, overriding any value present in the
 * response, so a provider cannot claim that the user belongs to another provider. When more than one OAuth 2.0 client is
 * configured (or {@code micronaut.security.oauth2.openid.qualify-username-with-provider} is {@code true}), the username is qualified as {@code providerName:subject} so that a subject at one provider never
 * collides with the same subject at another provider. A qualified username is only unambiguous if the provider name does
 * not contain the separator, otherwise the provider {@code alpha} with the subject {@code beta:victim} and the provider
 * {@code alpha:beta} with the subject {@code victim} are the same user. Creating a validator which qualifies usernames
 * for a provider whose name contains {@value #PROVIDER_SEPARATOR} fails with a {@link ConfigurationException}.
 * </p>
 * <p>
 * The endpoint may be resolved lazily: if the supplier throws (for example because the OpenID provider metadata is not
 * available yet) the token is not validated by this validator and the resolution is retried on the next validation.
 * </p>
 */
@Internal
final class UserInfoClientTokenValidator implements Closeable, TokenValidator<HttpRequest<?>>, Named {
    /**
     * Separator between the provider name and the subject in the username when several OAuth 2.0 clients are configured.
     */
    static final String PROVIDER_SEPARATOR = ":";
    private static final Logger LOG = LoggerFactory.getLogger(UserInfoClientTokenValidator.class);
    private static final Argument<Map<String, Object>> MAP_ARGUMENT = Argument.mapOf(String.class, Object.class);
    private final String name;
    private final boolean qualifyUsername;
    private final Supplier<Optional<Endpoint>> endpointSupplier;
    private volatile boolean resolved;
    @Nullable
    private Endpoint endpoint;

    /**
     * @param name Provider name
     * @param httpClient HTTP client pointing to the authorization server
     * @param path UserInfo endpoint path
     * @param qualifyUsername Whether to qualify the username with the provider name. See {@link io.micronaut.security.oauth2.configuration.OpenIdConfiguration#getQualifyUsernameWithProvider()}.
     * @throws ConfigurationException if {@code qualifyUsername} is {@code true} and {@code name} contains {@value #PROVIDER_SEPARATOR}
     */
    UserInfoClientTokenValidator(String name, HttpClient httpClient, String path, boolean qualifyUsername) {
        this(name, new Endpoint(httpClient, path), qualifyUsername);
    }

    /**
     * @param name Provider name
     * @param endpoint The already resolved UserInfo endpoint
     * @param qualifyUsername Whether to qualify the username with the provider name. See {@link io.micronaut.security.oauth2.configuration.OpenIdConfiguration#getQualifyUsernameWithProvider()}.
     * @throws ConfigurationException if {@code qualifyUsername} is {@code true} and {@code name} contains {@value #PROVIDER_SEPARATOR}
     */
    UserInfoClientTokenValidator(String name, @NonNull Endpoint endpoint, boolean qualifyUsername) {
        this(name, qualifyUsername, () -> Optional.of(endpoint));
        this.endpoint = endpoint;
        this.resolved = true;
    }

    /**
     * @param name Provider name
     * @param qualifyUsername Whether to qualify the username with the provider name. See {@link io.micronaut.security.oauth2.configuration.OpenIdConfiguration#getQualifyUsernameWithProvider()}.
     * @param endpointSupplier Supplies the UserInfo endpoint. An empty optional means the provider exposes no UserInfo endpoint and is cached; an exception is not cached and the supplier is invoked again on the next validation.
     * @throws ConfigurationException if {@code qualifyUsername} is {@code true} and {@code name} contains {@value #PROVIDER_SEPARATOR}
     */
    UserInfoClientTokenValidator(String name, boolean qualifyUsername, @NonNull Supplier<Optional<Endpoint>> endpointSupplier) {
        if (qualifyUsername && name.contains(PROVIDER_SEPARATOR)) {
            throw new ConfigurationException("OAuth 2.0 client name '" + name + "' must not contain '" + PROVIDER_SEPARATOR
                + "' because usernames of authentications validated via the UserInfo endpoint are qualified as <provider name>"
                + PROVIDER_SEPARATOR + "<sub>. Rename the client under micronaut.security.oauth2.clients or set micronaut.security.oauth2.openid.qualify-username-with-provider to false");
        }
        this.name = name;
        this.qualifyUsername = qualifyUsername;
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

    /**
     * Builds an {@link Authentication} bound to this provider from the claims returned by its UserInfo endpoint.
     * @param claims Claims returned by the UserInfo endpoint
     * @return {@code null} if the response has no {@code sub} claim. Otherwise, an authentication whose {@link OauthAuthenticationMapper#PROVIDER_KEY} attribute is this provider's name.
     */
    @Nullable
    private Authentication createAuthentication(@NonNull Map<String, Object> claims) {
        Object subject = claims.get(Claims.SUBJECT);
        if (subject == null) {
            return null;
        }
        Map<String, Object> attributes = new HashMap<>(claims);
        Object claimedProvider = attributes.put(OauthAuthenticationMapper.PROVIDER_KEY, name);
        if (claimedProvider != null && !name.equals(claimedProvider) && LOG.isWarnEnabled()) {
            LOG.warn("UserInfo response of client {} claimed to belong to provider {}. Ignoring it", getName(), claimedProvider);
        }
        String username = qualifyUsername ? name + PROVIDER_SEPARATOR + subject : subject.toString();
        return Authentication.build(username, attributes);
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
