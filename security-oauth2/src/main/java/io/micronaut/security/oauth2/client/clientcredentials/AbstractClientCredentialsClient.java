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
package io.micronaut.security.oauth2.client.clientcredentials;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.core.annotation.Internal;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Abstract class to create a Client for client credentials grant.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Internal
public abstract class AbstractClientCredentialsClient implements ClientCredentialsClient {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractClientCredentialsClient.class);
    private static final String NOSCOPE = "NOSCOPE";
    private static final int FINGERPRINT_BYTES = 4;
    protected final TokenEndpointClient tokenEndpointClient;
    protected final OauthClientConfiguration oauthClientConfiguration;
    protected final Map<String, Publisher<CachedTokenResponse>> scopeToPublisherMap = new ConcurrentHashMap<>();

    /**
     * @param tokenEndpointClient The token endpoint client
     * @param oauthClientConfiguration The client configuration
     */
    public AbstractClientCredentialsClient(@NonNull OauthClientConfiguration oauthClientConfiguration,
                                           @NonNull TokenEndpointClient tokenEndpointClient) {
        this.oauthClientConfiguration = oauthClientConfiguration;
        this.tokenEndpointClient = tokenEndpointClient;
    }

    /**
     *
     * @return the bean's name;
     */
    public String getName() {
        return oauthClientConfiguration.getName();
    }

    @NonNull
    @Override
    public Publisher<TokenResponse> requestToken(@Nullable String scope) {
        return requestToken(scope, false);
    }

    @Override
    @NonNull
    public Publisher<TokenResponse> requestToken(@Nullable String scope, boolean force) {
        String resolvedScope = scope != null ? scope : NOSCOPE;
        return Flux.from(scopeToPublisherMap.computeIfAbsent(resolvedScope, k -> cachedTokenResponseForScope(scope)))
            .flatMap((Function<CachedTokenResponse, Mono<TokenResponse>>) cached -> {
                if (!force && !isExpired(cached)) {
                    return Mono.just(cached.tokenResponse());
                }
                return Mono.from(scopeToPublisherMap.computeIfPresent(resolvedScope, (s, tokenResponse) -> cachedTokenResponseForScope(scope)))
                    .map(CachedTokenResponse::tokenResponse);
            }).doOnError(error -> {
                scopeToPublisherMap.remove(resolvedScope);
            });
    }

    @NonNull
    private Publisher<CachedTokenResponse> cachedTokenResponseForScope(String scope) {
        return Flux.from(tokenEndpointClient.sendRequest(createTokenRequestContext(scope)))
            .map(this::toCachedTokenResponse)
            .cache();
    }

    @NonNull
    private CachedTokenResponse toCachedTokenResponse(@NonNull TokenResponse tokenResponse) {
        Instant expiresAt = expiresAt(tokenResponse);
        if (LOG.isTraceEnabled()) {
            LOG.trace("caching client credentials access token (sha256 prefix {}) for OAuth 2.0 client {} until {}",
                fingerprint(tokenResponse.getAccessToken()), getName(), expiresAt);
        }
        return new CachedTokenResponse(tokenResponse, expiresAt);
    }

    private boolean isExpired(@NonNull CachedTokenResponse cached) {
        boolean isExpired = isExpired(cached.expiresAt());
        if (isExpired && LOG.isTraceEnabled()) {
            LOG.trace("client credentials access token (sha256 prefix {}) for OAuth 2.0 client {} expired at {}",
                fingerprint(cached.tokenResponse().getAccessToken()), getName(), cached.expiresAt());
        }
        return isExpired;
    }

    /**
     * Computes the instant at which the access token expires. It is invoked once, when the token response is cached.
     *
     * @param tokenResponse Token Response
     * @return The expiration derived from {@code expires_in} if present, otherwise from the {@code exp} claim if the access token is a JWT,
     * otherwise the current instant plus {@link ClientCredentialsConfiguration#getDefaultExpiration()}.
     * @since 5.4.0
     */
    @NonNull
    protected Instant expiresAt(@NonNull TokenResponse tokenResponse) {
        return tokenResponse.getExpiresInDate()
            .map(Date::toInstant)
            .or(() -> jwtExpirationDate(tokenResponse).map(Date::toInstant))
            .orElseGet(() -> Instant.now().plus(defaultExpiration()));
    }

    /**
     *
     * @param tokenResponse Token Response
     * @return true if any A) parameter token response is null B) if an expiration time cannot parsed C) (expiration date - {@link ClientCredentialsConfiguration#getAdvancedExpiration()}) before current date.
     */
    protected boolean isExpired(@Nullable TokenResponse tokenResponse) {
        if (tokenResponse == null) {
            return true;
        }
        return expirationDate(tokenResponse).map(this::isExpired).orElse(true);
    }

    /**
     *
     * @param expiresAt Expiration
     * @return true if the (expiration - {@link ClientCredentialsConfiguration#getAdvancedExpiration()}) is before the current instant.
     * @since 5.4.0
     */
    protected boolean isExpired(@NonNull Instant expiresAt) {
        return expiresAt.minus(advancedExpiration()).isBefore(Instant.now());
    }

    /**
     *
     * @param expirationDate Expiration
     * @return true if the (expiration date - {@link ClientCredentialsConfiguration#getAdvancedExpiration()}) before current date.
     */
    protected boolean isExpired(@NonNull Date expirationDate) {
        return isExpired(expirationDate.toInstant());
    }

    /**
     *
     * @param tokenResponse Token Response
     * @return The expiration date from the exp claim in the access token is a JWT or the expiration date calculated from the expiresIn
     */
    protected Optional<Date> expirationDate(@NonNull TokenResponse tokenResponse) {
        return jwtExpirationDate(tokenResponse).or(tokenResponse::getExpiresInDate);
    }

    @NonNull
    private Optional<Date> jwtExpirationDate(@NonNull TokenResponse tokenResponse) {
        try {
            JWT jwt = JWTParser.parse(tokenResponse.getAccessToken());
            return Optional.ofNullable(jwt.getJWTClaimsSet().getExpirationTime());
        } catch (ParseException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("client credentials access token (sha256 prefix {}) for OAuth 2.0 client {} cannot be parsed as a JWT",
                    fingerprint(tokenResponse.getAccessToken()), getName());
            }
        }
        return Optional.empty();
    }

    @NonNull
    private Duration advancedExpiration() {
        return oauthClientConfiguration.getClientCredentials()
            .map(ClientCredentialsConfiguration::getAdvancedExpiration)
            .orElse(OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION);
    }

    @NonNull
    private Duration defaultExpiration() {
        return oauthClientConfiguration.getClientCredentials()
            .map(ClientCredentialsConfiguration::getDefaultExpiration)
            .orElse(ClientCredentialsConfiguration.DEFAULT_EXPIRATION);
    }

    @NonNull
    private static String fingerprint(@Nullable String accessToken) {
        if (accessToken == null) {
            return "null";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(accessToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, FINGERPRINT_BYTES);
        } catch (NoSuchAlgorithmException e) {
            return "unavailable";
        }
    }

    /**
     *
     * @param scope The requested scope for the client credentials request
     * @return A client credentials token request context
     */
    protected abstract ClientCredentialsTokenRequestContext createTokenRequestContext(@Nullable String scope);

    /**
     * A token response together with the expiration computed when it was received.
     *
     * @param tokenResponse The token response
     * @param expiresAt The instant at which the access token expires
     * @since 5.4.0
     */
    protected record CachedTokenResponse(@NonNull TokenResponse tokenResponse, @NonNull Instant expiresAt) {
    }
}
