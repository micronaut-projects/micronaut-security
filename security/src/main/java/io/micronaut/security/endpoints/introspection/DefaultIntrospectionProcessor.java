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
package io.micronaut.security.endpoints.introspection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.errors.OauthErrorResponseException;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.security.token.refresh.RefreshTokenPersistence;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Validates the {@link IntrospectionRequest#getToken()} with the available {@link TokenValidator}.
 * Then it creates a {@link IntrospectionResponse} with the first {@link Authentication} object.
 * If no TokenValidator is able to validate the token, it tries with {@link RefreshTokenValidator}.
 * A refresh token whose format is valid is then looked up in {@link RefreshTokenPersistence}, when such a bean exists,
 * so that a revoked refresh token is reported as inactive. If no {@link RefreshTokenPersistence} bean exists,
 * a refresh token is reported active as soon as the {@link RefreshTokenValidator} accepts it.
 * If it cannot authenticate it returns {active: false}
 * @author Sergio del Amo
 * @since 2.1.0
 * @param <T> Request
 */
@Singleton
public class DefaultIntrospectionProcessor<T> implements IntrospectionProcessor<T> {
    public static final String CLIENT_ID = "client_id";
    public static final String USERNAME = "username";
    public static final String TOKEN_TYPE = "token_type";
    public static final String ISSUER     = "iss";
    public static final String SUBJECT    = "sub";
    public static final String EXP        = "exp";
    public static final String NOT_BEFORE = "nbf";
    public static final String ISSUED_AT  = "iat";
    public static final String JWT_ID     = "jti";
    public static final String AUDIENCE   = "aud";
    public static final String SCOPE      = "scope";

    public static final List<String> FIELDS_ATTRIBUTE_NAMES = Arrays.asList(SCOPE,
            USERNAME,
            CLIENT_ID,
            TOKEN_TYPE,
            EXP,
            ISSUED_AT,
            SUBJECT,
            NOT_BEFORE,
            AUDIENCE,
            ISSUER,
            JWT_ID);

    protected static final Logger LOG = LoggerFactory.getLogger(DefaultIntrospectionProcessor.class);
    protected final Collection<TokenValidator<T>> tokenValidators;
    protected final TokenConfiguration tokenConfiguration;
    @Nullable
    protected final RefreshTokenValidator refreshTokenValidator;
    @Nullable
    protected final RefreshTokenPersistence refreshTokenPersistence;

    /**
     * @param tokenValidators Token validators
     * @param tokenConfiguration Token configuration
     * @param refreshTokenValidator Refresh token validator
     * @deprecated Use {@link #DefaultIntrospectionProcessor(Collection, TokenConfiguration, RefreshTokenValidator, RefreshTokenPersistence)} instead.
     */
    @Deprecated(since = "5.6.0", forRemoval = true)
    public DefaultIntrospectionProcessor(Collection<TokenValidator<T>> tokenValidators,
                                         TokenConfiguration tokenConfiguration,
                                         @Nullable RefreshTokenValidator refreshTokenValidator) {
        this(tokenValidators, tokenConfiguration, refreshTokenValidator, null);
    }

    /**
     * @param tokenValidators Token validators
     * @param tokenConfiguration Token configuration
     * @param refreshTokenValidator Refresh token validator
     * @param refreshTokenPersistence Refresh token persistence, consulted to detect revoked refresh tokens
     * @since 5.6.0
     */
    @Inject
    public DefaultIntrospectionProcessor(Collection<TokenValidator<T>> tokenValidators,
                                         TokenConfiguration tokenConfiguration,
                                         @Nullable RefreshTokenValidator refreshTokenValidator,
                                         @Nullable RefreshTokenPersistence refreshTokenPersistence) {
        this.tokenValidators = tokenValidators;
        this.tokenConfiguration = tokenConfiguration;
        this.refreshTokenValidator = refreshTokenValidator;
        this.refreshTokenPersistence = refreshTokenPersistence;
    }

    @NonNull
    @Override
    public Publisher<IntrospectionResponse> introspect(@NonNull IntrospectionRequest introspectionRequest,
                                                       @NonNull T requestContext) {
        String token = introspectionRequest.getToken();
        return Flux.fromIterable(tokenValidators)
                .concatMap(tokenValidator -> tokenValidator.validateToken(token, requestContext))
                .next()
                .map(authentication -> createIntrospectionResponse(authentication, requestContext))
                .switchIfEmpty(Mono.defer(() -> Mono.from(introspectRefreshToken(token, requestContext))))
                .flux();
    }

    /**
     * Introspects a token which no {@link TokenValidator} accepted, treating it as a refresh token.
     * Only invoked when every {@link TokenValidator} emitted empty.
     * <ul>
     *     <li>If there is no {@link RefreshTokenValidator} or no {@link RefreshTokenPersistence} bean, there is no revocation
     *     point to consult and the response is the one built by {@link #emptyIntrospectionResponse(String)}:
     *     active only if a {@link RefreshTokenValidator} accepts the token. Subclasses overriding that method keep being honoured.</li>
     *     <li>If the {@link RefreshTokenValidator} rejects the token, the token is reported inactive.</li>
     *     <li>Otherwise the token is reported active only if {@link RefreshTokenPersistence#getAuthentication(String)}
     *     emits an {@link Authentication}; an empty publisher or an error, emitted or thrown, means the token is reported inactive.
     *     {@link RefreshTokenPersistence#getAuthentication(String)} must therefore not have side effects, such as marking the refresh token as used.</li>
     * </ul>
     * No work is done until the returned publisher is subscribed.
     * @param token Token
     * @param requestContext Request context
     * @return Introspection Response
     * @since 5.6.0
     */
    @NonNull
    protected Publisher<IntrospectionResponse> introspectRefreshToken(@NonNull String token, @NonNull T requestContext) {
        if (refreshTokenValidator == null || refreshTokenPersistence == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("No RefreshTokenValidator or no RefreshTokenPersistence bean present. Skipping the RefreshTokenPersistence lookup");
            }
            return Mono.fromSupplier(() -> emptyIntrospectionResponse(token));
        }
        RefreshTokenValidator validator = refreshTokenValidator;
        RefreshTokenPersistence persistence = refreshTokenPersistence;
        return Mono.defer(() -> {
            Optional<String> refreshTokenKey = validator.validate(token);
            if (refreshTokenKey.isEmpty()) {
                return Mono.just(inactiveIntrospectionResponse());
            }
            String key = refreshTokenKey.get();
            return Mono.defer(() -> Mono.from(persistence.getAuthentication(key)))
                    .onErrorResume(t -> {
                        logRefreshTokenPersistenceError(t);
                        return Mono.empty();
                    })
                    .map(authentication -> createIntrospectionResponse(authentication, requestContext))
                    .defaultIfEmpty(inactiveIntrospectionResponse());
        });
    }

    private static void logRefreshTokenPersistenceError(Throwable t) {
        if (t instanceof OauthErrorResponseException e) {
            // The OAuth 2.0 error a RefreshTokenPersistence emits to reject a revoked or unknown refresh token.
            if (LOG.isDebugEnabled()) {
                LOG.debug("RefreshTokenPersistence rejected the refresh token with {}. Reporting it inactive", e.getError());
            }
        } else if (LOG.isWarnEnabled()) {
            LOG.warn("RefreshTokenPersistence failed to resolve the refresh token. Reporting it inactive", t);
        }
    }

    /**
     * @return An {@link IntrospectionResponse} with {@code active: false} and no other fields.
     * @since 5.6.0
     */
    @NonNull
    protected IntrospectionResponse inactiveIntrospectionResponse() {
        return introspectionResponse(false);
    }

    /**
     *
     * Response for a token which no {@link TokenValidator} accepted, when there is no {@link RefreshTokenPersistence} to consult.
     * @param token Token
     * @return Introspection Response
     * @deprecated Only used when there is no {@link RefreshTokenPersistence} bean. Override {@link #introspectRefreshToken(String, Object)} instead, which also consults {@link RefreshTokenPersistence}.
     */
    @Deprecated(since = "5.6.0", forRemoval = true)
    @NonNull
    protected IntrospectionResponse emptyIntrospectionResponse(@NonNull String token) {
        return refreshTokenValidator != null && refreshTokenValidator.validate(token).isPresent()
            ? introspectionResponse(true)
            : inactiveIntrospectionResponse();
    }

    @NonNull
    private static IntrospectionResponse introspectionResponse(boolean active) {
        return new IntrospectionResponse(active,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null);
    }

    @NonNull
    @Override
    public Publisher<IntrospectionResponse> introspect(@NonNull Authentication authentication,
                                                       @NonNull T requestContext) {
        return Flux.just(createIntrospectionResponse(authentication, requestContext));
    }

    /**
     * Creates an {@link IntrospectionResponse} for an {@link Authentication}.
     * @param authentication Authentication
     * @param requestContext HTTP Request
     * @return an {@link IntrospectionResponse}
     */
    @NonNull
    public IntrospectionResponse createIntrospectionResponse(@NonNull Authentication authentication,
                                                             @NonNull T requestContext) {
        return new IntrospectionResponse(true,
            resolveTokenType(authentication).orElse(null),
            resolveScope(authentication).orElse(null),
            resolveClientId(authentication).orElse(null),
            resolveUsername(authentication).orElse(authentication.getName()),
            resolveExpiration(authentication).orElse(null),
            resolveIssuedAt(authentication).orElse(null),
            resolveNotBefore(authentication).orElse(null),
            resolveSub(authentication),
            resolveAud(authentication).orElse(null),
            resolveIssuer(authentication).orElse(null),
            resolveJwtId(authentication).orElse(null),
            resolveExtensions(authentication));
    }

    /**
     *
     * @param authentication Authentication
     * @return Introspection response extensions
     */
    @NonNull
    protected Map<String, Object> resolveExtensions(@NonNull Authentication authentication) {
        Map<String, Object> extensions = new HashMap<>();
        for (String k : authentication.getAttributes().keySet()) {
            if (FIELDS_ATTRIBUTE_NAMES.contains(k)) {
                continue;
            }
            Object value = authentication.getAttributes().get(k);
            if (value != null) {
                extensions.put(k, value);
            }
        }
        if (!extensions.containsKey(tokenConfiguration.getRolesName())) {
            extensions.put(tokenConfiguration.getRolesName(), new ArrayList<>(authentication.getRoles()));
        }
        return extensions;
    }

    /**
     * Populates the introspection response scope.
     * @param authentication Authentication
     * @return the scope
     */
    protected Optional<String> resolveScope(@NonNull Authentication authentication) {
        return attributeAsString(authentication, SCOPE);
    }

    /**
     * Populates the introspection response token type.
     * @param authentication Authentication
     * @return the Token type
     */
    @NonNull
    protected Optional<String> resolveTokenType(@NonNull Authentication authentication) {
        return attributeAsString(authentication, TOKEN_TYPE);
    }

    /**
     * Populates the introspection response client_id.
     * @param authentication Authentication
     * @return client_id value
     */
    @NonNull
    protected Optional<String> resolveClientId(@NonNull Authentication authentication) {
        return attributeAsString(authentication, CLIENT_ID);
    }

    /**
     * Populates the introspection response with aud claim.
     * @param authentication Authentication
     * @return value of aud claim
     */
    @NonNull
    protected Optional<String> resolveAud(@NonNull Authentication authentication) {
        return attributeAsString(authentication, AUDIENCE);
    }

    /**
     * Populates the introspection response with sub claim.
     * @param authentication Authentication
     * @return value of sub claim
     */
    @NonNull
    protected String resolveSub(@NonNull Authentication authentication) {
        return attributeAsString(authentication, SUBJECT).orElse(authentication.getName());
    }

    /**
     * Populates the introspection response with iss claim.
     * @param authentication Authentication
     * @return value of iss claim
     */
    @NonNull
    protected Optional<String> resolveIssuer(@NonNull Authentication authentication) {
        return attributeAsString(authentication, ISSUER);
    }

    /**
     * Populates the introspection response with jti username.
     * @param authentication Authentication
     * @return the jti claim value
     */
    @NonNull
    protected Optional<String> resolveJwtId(@NonNull Authentication authentication) {
        return attributeAsString(authentication, JWT_ID);

    }

    /**
     * Populates the introspection response with the username.
     * @param authentication Authentication
     * @return the username
     */
    @NonNull
    protected Optional<String> resolveUsername(@NonNull Authentication authentication) {
        return attributeAsString(authentication, USERNAME);
    }

    /**
     * Populates the introspection response with the exp claim of authentication.
     * @param authentication Authentication
     * @return the exp claim
     */
    protected Optional<Long> resolveExpiration(@NonNull Authentication authentication) {
        return secondsSinceEpochOfAttribute(EXP, authentication);
    }

    /**
     *
     * @param attributeName The attribute name e.g. exp nbf iat
     * @param authentication Authentication
     * @return An empty optional if the authentication attribute is not found, is null or it cannot be transformed to epoch seconds
     */
    protected Optional<Long> secondsSinceEpochOfAttribute(@NonNull String attributeName,
                                                          @NonNull Authentication authentication) {
        Object obj = authentication.getAttributes().get(attributeName);
        if (obj != null) {
            if (obj instanceof Long) {
                return Optional.of((Long) obj);
            } else if (obj instanceof Date) {
                return Optional.of(toSecondsSinceEpoch((Date) obj));
            } else {
                try {
                    return Optional.of(Long.valueOf(obj.toString()));
                } catch (NumberFormatException e) {
                    if (LOG.isWarnEnabled()) {
                        LOG.warn("cannot convert attribute {} with value {} to Integer", attributeName, obj);
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Populates the introspection response with the nbf claim of authentication.
     * @param authentication Authentication
     * @return value for nbf claim
     */
    @NonNull
    protected Optional<Long> resolveNotBefore(@NonNull Authentication authentication) {
        return secondsSinceEpochOfAttribute(NOT_BEFORE, authentication);
    }

    /**
     * Populates the introspection response with the iat claim of authentication.
     * @param authentication Authentication
     * @return value for iat claim
     */
    @NonNull
    protected Optional<Long> resolveIssuedAt(@NonNull Authentication authentication) {
        return secondsSinceEpochOfAttribute(ISSUED_AT, authentication);
    }

    /**
     *
     * @param date Date
     * @return seconds since epoch
     */
    public static long toSecondsSinceEpoch(final Date date) {
        return date.getTime() / 1000L;
    }
    
    /**
     * Resolves an authentication attribute as a String. A {@code null} value is treated the same as an absent key.
     * @param authentication Authentication
     * @param attributeName The attribute name
     * @return The attribute value as a String, or an empty optional if the attribute is absent or null
     */
    @NonNull
    private Optional<String> attributeAsString(@NonNull Authentication authentication,
                                               @NonNull String attributeName) {
        return Optional.ofNullable(authentication.getAttributes().get(attributeName)).map(Object::toString);
    }
}
