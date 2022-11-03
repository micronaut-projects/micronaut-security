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
package io.micronaut.security.endpoints.introspection;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.config.TokenConfiguration;
import io.micronaut.security.token.validator.RefreshTokenValidator;
import io.micronaut.security.token.validator.TokenValidator;
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

/**
 * Validates the {@link IntrospectionRequest#getToken()} with the available {@link TokenValidator}.
 * Then it creates a {@link IntrospectionResponse} with the first {@link Authentication} object.
 * If no TokenValidator is able to validate the token, it tries with {@link RefreshTokenValidator}.
 * If it cannot authenticate it returns {active: false}
 * @author Sergio del Amo
 * @since 2.1.0
 */
@Singleton
public class DefaultIntrospectionProcessor implements IntrospectionProcessor {
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
    protected final Collection<TokenValidator> tokenValidators;
    protected final TokenConfiguration tokenConfiguration;
    protected final RefreshTokenValidator refreshTokenValidator;

    public DefaultIntrospectionProcessor(Collection<TokenValidator> tokenValidators,
                                         TokenConfiguration tokenConfiguration,
                                         @Nullable RefreshTokenValidator refreshTokenValidator) {
        this.tokenValidators = tokenValidators;
        this.tokenConfiguration = tokenConfiguration;
        this.refreshTokenValidator = refreshTokenValidator;
    }

    @NonNull
    @Override
    public Publisher<IntrospectionResponse> introspect(@NonNull IntrospectionRequest introspectionRequest,
                                                       @NonNull HttpRequest<?> httpRequest) {
        String token = introspectionRequest.getToken();
        return Flux.fromIterable(tokenValidators)
                .flatMap(tokenValidator -> tokenValidator.validateToken(token, httpRequest))
                .next()
                .map(authentication -> createIntrospectionResponse(authentication, httpRequest))
                .defaultIfEmpty(emptyIntrospectionResponse(token))
                .flux();
    }

    /**
     *
     * Empty response for introspection response.
     * @param token Token
     * @return Introspection Response
     */
    @NonNull
    protected IntrospectionResponse emptyIntrospectionResponse(@NonNull String token) {
        return new IntrospectionResponse(refreshTokenValidator != null && refreshTokenValidator.validate(token).isPresent(),
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
                                                       @NonNull HttpRequest<?> httpRequest) {
        return Flux.just(createIntrospectionResponse(authentication, httpRequest));
    }

    /**
     * Creates an {@link IntrospectionResponse} for an {@link Authentication}.
     * @param authentication Authentication
     * @param httpRequest HTTP Request
     * @return an {@link IntrospectionResponse}
     */
    @NonNull
    public IntrospectionResponse createIntrospectionResponse(@NonNull Authentication authentication,
                                                             @NonNull HttpRequest<?> httpRequest) {
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
            extensions.put(k, authentication.getAttributes().get(k));
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
        return (authentication.getAttributes().containsKey(SCOPE)) ?
            Optional.of(authentication.getAttributes().get(SCOPE).toString()) :
            Optional.empty();
    }

    /**
     * Populates the introspection response token type.
     * @param authentication Authentication
     * @return the Token type
     */
    @NonNull
    protected Optional<String> resolveTokenType(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(TOKEN_TYPE)) ?
            Optional.of(authentication.getAttributes().get(TOKEN_TYPE).toString()) :
            Optional.empty();
    }

    /**
     * Populates the introspection response client_id.
     * @param authentication Authentication
     * @return client_id value
     */
    @NonNull
    protected Optional<String> resolveClientId(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(CLIENT_ID)) ?
            Optional.of(authentication.getAttributes().get(CLIENT_ID).toString()) :
            Optional.empty();
    }

    /**
     * Populates the introspection response with aud claim.
     * @param authentication Authentication
     * @return value of aud claim
     */
    @NonNull
    protected Optional<String> resolveAud(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(AUDIENCE)) ?
            Optional.of(authentication.getAttributes().get(AUDIENCE).toString()) :
            Optional.empty();
    }

    /**
     * Populates the introspection response with sub claim.
     * @param authentication Authentication
     * @return value of sub claim
     */
    @NonNull
    protected String resolveSub(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(SUBJECT)) ?
            authentication.getAttributes().get(SUBJECT).toString() :
            authentication.getName();
    }

    /**
     * Populates the introspection response with iss claim.
     * @param authentication Authentication
     * @return value of iss claim
     */
    @NonNull
    protected Optional<String> resolveIssuer(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(ISSUER)) ?
            Optional.of(authentication.getAttributes().get(ISSUER).toString()) :
            Optional.empty();
    }

    /**
     * Populates the introspection response with jti username.
     * @param authentication Authentication
     * @return the jti claim value
     */
    @NonNull
    protected Optional<String> resolveJwtId(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(JWT_ID)) ?
            Optional.of(authentication.getAttributes().get(JWT_ID).toString()) :
            Optional.empty();

    }

    /**
     * Populates the introspection response with the username.
     * @param authentication Authentication
     * @return the username
     */
    @NonNull
    protected Optional<String> resolveUsername(@NonNull Authentication authentication) {
        return (authentication.getAttributes().containsKey(USERNAME)) ?
            Optional.of(authentication.getAttributes().get(USERNAME).toString()) :
            Optional.empty();
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
     * @return An empty optional if the authentication attribute is not found or it cannot be transformed to epoch seconds
     */
    protected Optional<Long> secondsSinceEpochOfAttribute(@NonNull String attributeName,
                                                          @NonNull Authentication authentication) {
        if (authentication.getAttributes().containsKey(attributeName)) {
            Object obj = authentication.getAttributes().get(attributeName);
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
}
