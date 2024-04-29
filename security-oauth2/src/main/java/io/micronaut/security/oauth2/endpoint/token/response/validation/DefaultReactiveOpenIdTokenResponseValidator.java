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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.ReactiveJsonWebTokenValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.Collection;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link ReactiveOpenIdTokenResponseValidator}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
public class DefaultReactiveOpenIdTokenResponseValidator implements ReactiveOpenIdTokenResponseValidator<JWT> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultReactiveOpenIdTokenResponseValidator.class);
    private final Collection<OpenIdClaimsValidator> openIdClaimsValidators;
    private final Collection<GenericJwtClaimsValidator<HttpRequest<?>>> genericJwtClaimsValidators;
    private final NonceClaimValidator nonceClaimValidator;
    private final ReactiveJsonWebTokenValidator<JWT, HttpRequest<?>> jwtTokenValidator;

    /**
     * @param idTokenValidators OpenID JWT claim validators
     * @param genericJwtClaimsValidators Generic JWT claim validators
     * @param nonceClaimValidator The nonce claim validator
     * @param jwtTokenValidator Reactive JSON Web Token (JWT) validator
     */
    public DefaultReactiveOpenIdTokenResponseValidator(Collection<OpenIdClaimsValidator> idTokenValidators,
                                                       Collection<GenericJwtClaimsValidator<HttpRequest<?>>> genericJwtClaimsValidators,
                                                       @Nullable NonceClaimValidator nonceClaimValidator,
                                                       ReactiveJsonWebTokenValidator<JWT, HttpRequest<?>> jwtTokenValidator) {
        this.openIdClaimsValidators = idTokenValidators;
        this.genericJwtClaimsValidators = genericJwtClaimsValidators;
        this.nonceClaimValidator = nonceClaimValidator;
        this.jwtTokenValidator = jwtTokenValidator;
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWT> validate(OauthClientConfiguration clientConfiguration,
                                 OpenIdProviderMetadata openIdProviderMetadata,
                                 OpenIdTokenResponse openIdTokenResponse,
                                 @Nullable String nonce) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Validating the JWT signature using the JWKS uri [{}]", openIdProviderMetadata.getJwksUri());
        }
        return Mono.from(jwtTokenValidator.validate(openIdTokenResponse.getIdToken(), ServerRequestContext.currentRequest().orElse(null)))
                .filter(jwt -> validateClaims(clientConfiguration, openIdProviderMetadata, jwt, nonce));
    }

    /**
     *
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param jwt JWT with valida signature
     * @param nonce The persisted nonce value
     * @return the same JWT supplied as a parameter if the claims validation were succesful or empty if not.
     */
    @NonNull
    private boolean validateClaims(@NonNull OauthClientConfiguration clientConfiguration,
                                           @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                           @NonNull JWT jwt,
                                           @Nullable String nonce) {
        try {
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            OpenIdClaims claims = new JWTOpenIdClaims(claimsSet);
            if (genericJwtClaimsValidators.stream().allMatch(validator -> validator.validate(claims, null))) {
                if (openIdClaimsValidators.stream().allMatch(validator ->
                        validator.validate(claims, clientConfiguration, openIdProviderMetadata))) {
                    if (nonceClaimValidator == null) {
                        if (LOG.isTraceEnabled()) {
                            LOG.trace("Skipping nonce validation because no bean of type {} present. ", NonceClaimValidator.class.getSimpleName());
                        }
                        return true;
                    }
                    if (nonceClaimValidator.validate(claims, clientConfiguration, openIdProviderMetadata, nonce)) {
                        return true;
                    } else if (LOG.isErrorEnabled()) {
                        LOG.error("Nonce {} validation failed for claims {}", nonce, claims.getClaims().keySet().stream().map(key -> key + "=" + claims.getClaims().get(key)).collect(Collectors.joining(", ", "{", "}")));
                    }
                } else if (LOG.isErrorEnabled()) {
                    LOG.error("JWT OpenID specific claims validation failed for provider [{}]", clientConfiguration.getName());
                }
            } else if (LOG.isErrorEnabled()) {
                LOG.error("JWT generic claims validation failed for provider [{}]", clientConfiguration.getName());
            }
        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to parse the JWT returned from provider [{}]", clientConfiguration.getName(), e);
            }
        }
        return false;
    }

    /**
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * Uses the ID token in the OpenID connect response to extract a JSON Web token and validates its signature
     * @return A JWT if the signature validation is successful
     */
    @NonNull
    protected Publisher<JWT> parseJwtWithValidSignature(@NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                                       @NonNull OpenIdTokenResponse openIdTokenResponse) {
        return jwtTokenValidator.validate(openIdTokenResponse.getIdToken(), ServerRequestContext.currentRequest().orElse(null));
    }
}
