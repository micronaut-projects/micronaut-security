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
package io.micronaut.security.token.generator;

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.event.AccessTokenGeneratedEvent;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.render.AccessRefreshToken;
import io.micronaut.security.token.render.TokenRenderer;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Generates http responses with access and refresh token.
 *
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Requires(beans = {
    AccessTokenConfiguration.class,
    TokenRenderer.class,
    TokenGenerator.class,
    ClaimsGenerator.class
})
@Singleton
public class DefaultAccessRefreshTokenGenerator implements AccessRefreshTokenGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAccessRefreshTokenGenerator.class);

    protected final BeanContext beanContext;
    protected final RefreshTokenGenerator refreshTokenGenerator;
    protected final ClaimsGenerator claimsGenerator;
    protected final AccessTokenConfiguration accessTokenConfiguration;
    protected final TokenRenderer tokenRenderer;
    protected final TokenGenerator tokenGenerator;
    protected final ApplicationEventPublisher<RefreshTokenGeneratedEvent> refreshTokenGeneratedEventPublisher;

    protected final ApplicationEventPublisher<AccessTokenGeneratedEvent> accessTokenGeneratedEventPublisher;

    /**
     * @param accessTokenConfiguration            The access token generator config
     * @param tokenRenderer                       The token renderer
     * @param tokenGenerator                      The token generator
     * @param beanContext                         Bean Context
     * @param refreshTokenGenerator               The refresh token generator
     * @param claimsGenerator                     Claims generator
     * @param refreshTokenGeneratedEventPublisher The Application event publisher for {@link RefreshTokenGeneratedEvent}.
     * @param accessTokenGeneratedEventPublisher The Application event publisher for {@link AccessTokenGeneratedEvent}.
     */
    public DefaultAccessRefreshTokenGenerator(AccessTokenConfiguration accessTokenConfiguration,
                                              TokenRenderer tokenRenderer,
                                              TokenGenerator tokenGenerator,
                                              BeanContext beanContext,
                                              @Nullable RefreshTokenGenerator refreshTokenGenerator,
                                              ClaimsGenerator claimsGenerator,
                                              ApplicationEventPublisher<RefreshTokenGeneratedEvent> refreshTokenGeneratedEventPublisher,
                                              ApplicationEventPublisher<AccessTokenGeneratedEvent> accessTokenGeneratedEventPublisher) {
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.tokenRenderer = tokenRenderer;
        this.tokenGenerator = tokenGenerator;
        this.beanContext = beanContext;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.claimsGenerator = claimsGenerator;
        this.refreshTokenGeneratedEventPublisher = refreshTokenGeneratedEventPublisher;
        this.accessTokenGeneratedEventPublisher = accessTokenGeneratedEventPublisher;
    }

    /**
     * Generate an {@link AccessRefreshToken} response for the given
     * user details.
     *
     * @param authentication Authenticated user's representation.
     * @return The http response
     */
    @NonNull
    @Override
    public Optional<AccessRefreshToken> generate(@NonNull Authentication authentication) {
        return generate(generateRefreshToken(authentication).orElse(null), authentication);
    }

    /**
     * Generates a refresh token and emits a {@link RefreshTokenGeneratedEvent}.
     * @param authentication Authenticated user's representation.
     * @return {@literal Optional#empty()} if refresh token was not generated or the refresh token wrapped in an Optional.
     */
    @NonNull
    public Optional<String> generateRefreshToken(@NonNull Authentication authentication) {
        Optional<String> refreshToken = Optional.empty();
        String msg = "Skipped refresh token generation because no {} implementation is present";
        if (beanContext.containsBean(RefreshTokenValidator.class)) {
            if (beanContext.containsBean(RefreshTokenPersistence.class)) {
                if (refreshTokenGenerator != null) {
                    String key = refreshTokenGenerator.createKey(authentication);
                    refreshToken = refreshTokenGenerator.generate(authentication, key);
                    refreshToken.ifPresent(t -> refreshTokenGeneratedEventPublisher.publishEvent(new RefreshTokenGeneratedEvent(authentication, key)));
                } else {
                    debug(LOG, msg, RefreshTokenGenerator.class.getName());
                }
            } else {
                debug(LOG, msg, RefreshTokenPersistence.class.getName());
            }
        } else {
            debug(LOG, msg, RefreshTokenValidator.class.getName());
        }

        return refreshToken;
    }

    /**
     * Generate an {@link AccessRefreshToken} response for the given
     * refresh token and claims.
     *
     * @param refreshToken The refresh token
     * @param oldClaims The claims to generate the access token
     * @return The http response
     */
    @NonNull
    public Optional<AccessRefreshToken> generate(@Nullable String refreshToken, @NonNull Map<String, ?> oldClaims) {
        Map<String, Object> claims = claimsGenerator.generateClaimsSet(oldClaims, accessTokenExpiration(oldClaims));

        Optional<String> optionalAccessToken = tokenGenerator.generateToken(claims);
        if (!optionalAccessToken.isPresent()) {
                debug(LOG, "tokenGenerator failed to generate access token claims: {}", claims.entrySet()
                        .stream()
                        .map(entry -> entry.getKey() + "=>" + entry.getValue().toString())
                        .collect(Collectors.joining(", ")));
            return Optional.empty();
        }
        String accessToken = optionalAccessToken.get();
        accessTokenGeneratedEventPublisher.publishEvent(new AccessTokenGeneratedEvent(accessToken));
        return Optional.of(tokenRenderer.render(accessTokenExpiration(oldClaims), accessToken, refreshToken));
    }

    /**
     * Generate a new access refresh token.
     *
     * @param refreshToken The refresh token
     * @param authentication The user details to create a new access token
     * @return The optional access refresh token
     */
    @NonNull
    @Override
    public Optional<AccessRefreshToken> generate(@Nullable String refreshToken, @NonNull Authentication authentication) {
        Optional<String> optionalAccessToken = tokenGenerator.generateToken(authentication, accessTokenExpiration(authentication));
        if (!optionalAccessToken.isPresent()) {
            debug(LOG, "Failed to generate access token for user {}", authentication.getName());
            return Optional.empty();
        }

        String accessToken = optionalAccessToken.get();
        accessTokenGeneratedEventPublisher.publishEvent(new AccessTokenGeneratedEvent(accessToken));
        return Optional.of(tokenRenderer.render(authentication, accessTokenExpiration(authentication), accessToken, refreshToken));
    }

    /**
     *
     * @param authentication User details for which the access token is being generated
     * @return expiration of the new access token
     */
    @NonNull
    public Integer accessTokenExpiration(@NonNull Authentication authentication) {
        return accessTokenConfiguration.getExpiration();
    }

    /**
     *
     * @param oldClaims The old claims used to build the new token
     * @return expiration of the new access token
     */
    @NonNull
    public Integer accessTokenExpiration(@NonNull Map<String, ?> oldClaims) {
        return accessTokenConfiguration.getExpiration();
    }
}
