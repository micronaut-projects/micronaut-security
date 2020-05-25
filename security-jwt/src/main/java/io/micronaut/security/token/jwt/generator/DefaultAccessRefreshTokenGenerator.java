/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.token.jwt.generator;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.context.BeanContext;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.token.generator.RefreshTokenGenerator;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.event.AccessTokenGeneratedEvent;
import io.micronaut.security.token.event.RefreshTokenGeneratedEvent;
import io.micronaut.security.token.jwt.generator.claims.ClaimsGenerator;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;
import io.micronaut.security.token.jwt.render.TokenRenderer;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Generates http responses with access and refresh token.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
public class DefaultAccessRefreshTokenGenerator implements AccessRefreshTokenGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(AccessRefreshTokenGenerator.class);

    protected final BeanContext beanContext;
    protected final RefreshTokenGenerator refreshTokenGenerator;
    protected final ClaimsGenerator claimsGenerator;
    protected final AccessTokenConfiguration accessTokenConfiguration;
    protected final TokenRenderer tokenRenderer;
    protected final TokenGenerator tokenGenerator;
    protected final ApplicationEventPublisher eventPublisher;

    /**
     *
     * @param accessTokenConfiguration The access token generator config
     * @param tokenRenderer The token renderer
     * @param tokenGenerator The token generator
     * @param beanContext Bean Context
     * @param refreshTokenGenerator The refresh token generator
     * @param claimsGenerator Claims generator
     * @param eventPublisher The Application event publiser
     */
    public DefaultAccessRefreshTokenGenerator(AccessTokenConfiguration accessTokenConfiguration,
                                       TokenRenderer tokenRenderer,
                                       TokenGenerator tokenGenerator,
                                       BeanContext beanContext,
                                       @Nullable RefreshTokenGenerator refreshTokenGenerator,
                                       ClaimsGenerator claimsGenerator,
                                       ApplicationEventPublisher eventPublisher) {
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.tokenRenderer = tokenRenderer;
        this.tokenGenerator = tokenGenerator;
        this.beanContext = beanContext;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.claimsGenerator = claimsGenerator;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Generate an {@link AccessRefreshToken} response for the given
     * user details.
     *
     * @param userDetails Authenticated user's representation.
     * @return The http response
     */
    @NonNull
    @Override
    public Optional<AccessRefreshToken> generate(@NonNull UserDetails userDetails) {
        return generate(generateRefreshToken(userDetails).orElse(null), userDetails);
    }

    /**
     * Generates a refresh token and emits a {@link RefreshTokenGeneratedEvent}.
     * @param userDetails Authenticated user's representation.
     * @return {@literal Optional#empty()} if refresh token was not generated or the refresh token wrapped in an Optional.
     */
    @NonNull
    public Optional<String> generateRefreshToken(@NonNull UserDetails userDetails) {
        Optional<String> refreshToken = Optional.empty();
        if (beanContext.containsBean(RefreshTokenValidator.class)) {
            if (beanContext.containsBean(RefreshTokenPersistence.class)) {
                if (refreshTokenGenerator != null) {
                    String key = refreshTokenGenerator.createKey(userDetails);
                    refreshToken = refreshTokenGenerator.generate(userDetails, key);
                    refreshToken.ifPresent(t -> eventPublisher.publishEvent(new RefreshTokenGeneratedEvent(userDetails, key)));
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Skipped refresh token generation because no {} implementation is present", RefreshTokenGenerator.class.getName());
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Skipped refresh token generation because no {} implementation is present", RefreshTokenPersistence.class.getName());
                }
            }
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipped refresh token generation because no {} implementation is present", RefreshTokenValidator.class.getName());
            }
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
    public Optional<AccessRefreshToken> generate(@NonNull String refreshToken, @NonNull Map<String, ?> oldClaims) {
        Map<String, Object> claims = claimsGenerator.generateClaimsSet(oldClaims, accessTokenExpiration(oldClaims));

        Optional<String> optionalAccessToken = tokenGenerator.generateToken(claims);
        if (!optionalAccessToken.isPresent()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("tokenGenerator failed to generate access token claims: {}", claims.entrySet()
                        .stream()
                        .map((entry) -> entry.getKey() + "=>" + entry.getValue().toString())
                        .collect(Collectors.joining(", ")));
            }
            return Optional.empty();
        }
        String accessToken = optionalAccessToken.get();
        eventPublisher.publishEvent(new AccessTokenGeneratedEvent(accessToken));
        return Optional.of(tokenRenderer.render(accessTokenExpiration(oldClaims), accessToken, refreshToken));
    }

    /**
     * Generate a new access refresh token.
     *
     * @param refreshToken The refresh token
     * @param userDetails The user details to create a new access token
     * @return The optional access refresh token
     */
    @NonNull
    @Override
    public Optional<AccessRefreshToken> generate(@NonNull String refreshToken, @NonNull UserDetails userDetails) {
        Optional<String> optionalAccessToken = tokenGenerator.generateToken(userDetails, accessTokenExpiration(userDetails));
        if (!optionalAccessToken.isPresent()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Failed to generate access token for user {}", userDetails.getUsername());
            }
            return Optional.empty();
        }

        String accessToken = optionalAccessToken.get();
        eventPublisher.publishEvent(new AccessTokenGeneratedEvent(accessToken));
        return Optional.of(tokenRenderer.render(userDetails, accessTokenExpiration(userDetails), accessToken, refreshToken));
    }

    /**
     *
     * @param userDetails User details for which the access token is being generated
     * @return expiration of the new access token
     */
    @NonNull
    public Integer accessTokenExpiration(@NonNull UserDetails userDetails) {
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
