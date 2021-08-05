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
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.inject.Singleton;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
                .defaultIfEmpty(new IntrospectionResponse(refreshTokenValidator != null && refreshTokenValidator.validate(token).isPresent()))
                .flux();
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
        IntrospectionResponse introspectionResponse = new IntrospectionResponse(true);
        List<String> processedAttributeNames = populateFields(authentication, introspectionResponse);
        Map<String, Object> extensions = new HashMap<>();
        for (String k : authentication.getAttributes().keySet()) {
            if (processedAttributeNames.contains(k)) {
                continue;
            }
            extensions.put(k, authentication.getAttributes().get(k));
        }
        if (!extensions.containsKey(tokenConfiguration.getRolesName())) {
            extensions.put(tokenConfiguration.getRolesName(), authentication.getRoles());
        }
        introspectionResponse.setExtensions(extensions);
        if (introspectionResponse.getUsername() == null) {
            introspectionResponse.setUsername(authentication.getName());
        }
        return introspectionResponse;
    }

    /**
     *
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     * @return A list of attribute names already processed
     */
    @NonNull
    protected List<String> populateFields(@NonNull Authentication authentication,
                                          @NonNull IntrospectionResponse introspectionResponse) {
        populateScope(authentication, introspectionResponse);
        populateUsername(authentication, introspectionResponse);
        populateClientId(authentication, introspectionResponse);
        populateTokenType(authentication, introspectionResponse);
        populateExpiration(authentication, introspectionResponse);
        populateIssuedAt(authentication, introspectionResponse);
        populateSub(authentication, introspectionResponse);
        populateNotBefore(authentication, introspectionResponse);
        populateAud(authentication, introspectionResponse);
        populateIssuer(authentication, introspectionResponse);
        populateJwtId(authentication, introspectionResponse);
        return FIELDS_ATTRIBUTE_NAMES;
    }

    /**
     * Populates the introspection response scope.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateScope(@NonNull Authentication authentication,
                                 @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(SCOPE)) {
            introspectionResponse.setScope(authentication.getAttributes().get(SCOPE).toString());
        }
    }

    /**
     * Populates the introspection response token type.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateTokenType(@NonNull Authentication authentication,
                                        @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(TOKEN_TYPE)) {
            introspectionResponse.setTokenType(authentication.getAttributes().get(TOKEN_TYPE).toString());
        }
    }

    /**
     * Populates the introspection response client_id.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateClientId(@NonNull Authentication authentication,
                                       @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(CLIENT_ID)) {
            introspectionResponse.setClientId(authentication.getAttributes().get(CLIENT_ID).toString());
        }
    }

    /**
     * Populates the introspection response with aud claim.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateAud(@NonNull Authentication authentication,
                               @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(AUDIENCE)) {
            introspectionResponse.setAud(authentication.getAttributes().get(AUDIENCE).toString());
        }
    }

    /**
     * Populates the introspection response with sub claim.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateSub(@NonNull Authentication authentication,
                               @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(SUBJECT)) {
            introspectionResponse.setSub(authentication.getAttributes().get(SUBJECT).toString());
        } else {
            introspectionResponse.setSub(authentication.getName());
        }
    }

    /**
     * Populates the introspection response with iss claim.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateIssuer(@NonNull Authentication authentication,
                                     @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(ISSUER)) {
            introspectionResponse.setIss(authentication.getAttributes().get(ISSUER).toString());
        }
    }

    /**
     * Populates the introspection response with jti username.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateJwtId(@NonNull Authentication authentication,
                                    @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(JWT_ID)) {
            introspectionResponse.setJti(authentication.getAttributes().get(JWT_ID).toString());
        }
    }

    /**
     * Populates the introspection response with the username.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateUsername(@NonNull Authentication authentication,
                                    @NonNull IntrospectionResponse introspectionResponse) {
        if (authentication.getAttributes().containsKey(USERNAME)) {
            introspectionResponse.setUsername(authentication.getAttributes().get(USERNAME).toString());
        }
    }

    /**
     * Populates the introspection response with the exp claim of authentication.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateExpiration(@NonNull Authentication authentication,
                                      @NonNull IntrospectionResponse introspectionResponse) {
        secondsSinceEpochOfAttribute(EXP, authentication).ifPresent(introspectionResponse::setExp);
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
                        LOG.warn("cannot convert attribute {} with value {} to Integer", attributeName, obj.toString());
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Populates the introspection response with the nbf claim of authentication.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateNotBefore(@NonNull Authentication authentication,
                                     @NonNull IntrospectionResponse introspectionResponse) {
        secondsSinceEpochOfAttribute(NOT_BEFORE, authentication).ifPresent(introspectionResponse::setNbf);
    }

    /**
     * Populates the introspection response with the iat claim of authentication.
     * @param authentication Authentication
     * @param introspectionResponse Introspection Response being populated
     */
    protected void populateIssuedAt(@NonNull Authentication authentication,
                                       @NonNull IntrospectionResponse introspectionResponse) {
        secondsSinceEpochOfAttribute(ISSUED_AT, authentication).ifPresent(introspectionResponse::setIat);
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
