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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.token.jwt.nimbus.ReactiveJwksSignature;
import io.micronaut.security.token.jwt.signature.ReactiveSignatureConfiguration;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JsonWebTokenParser;
import jakarta.inject.Singleton;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import java.text.ParseException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default implementation of {@link ReactiveOpenIdTokenResponseValidator}.
 * <p>
 * The ID token signature is verified exclusively against the JSON Web Key Set published at the
 * {@link OpenIdProviderMetadata#getJwksUri()} of the provider that issued it, as required by the
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation</a> section of the
 * OpenID Connect specification. The signature configurations used to validate request credentials are not consulted.
 *
 * @author Sergio del Amo
 * @since 4.8.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
@Internal
class DefaultReactiveOpenIdTokenResponseValidator implements ReactiveOpenIdTokenResponseValidator<JWT> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultReactiveOpenIdTokenResponseValidator.class);
    private final Collection<OpenIdClaimsValidator> openIdClaimsValidators;
    private final Collection<GenericJwtClaimsValidator<HttpRequest<?>>> genericJwtClaimsValidators;
    private final NonceClaimValidator nonceClaimValidator;
    private final JsonWebTokenParser<JWT> jsonWebTokenParser;
    private final JwkValidator jwkValidator;
    private final JwkSetFetcher<JWKSet> jwkSetFetcher;
    private final Map<JwksKey, ReactiveSignatureConfiguration<SignedJWT>> jwksSignatures = new ConcurrentHashMap<>();

    /**
     * @param idTokenValidators OpenID JWT claim validators
     * @param genericJwtClaimsValidators Generic JWT claim validators
     * @param nonceClaimValidator The nonce claim validator
     * @param jsonWebTokenParser JSON Web Token (JWT) parser
     * @param jwkValidator The JWK validator
     * @param jwkSetFetcher JSON Web Key Set fetcher
     */
    DefaultReactiveOpenIdTokenResponseValidator(@NonNull Collection<OpenIdClaimsValidator> idTokenValidators,
                                                @NonNull Collection<GenericJwtClaimsValidator<HttpRequest<?>>> genericJwtClaimsValidators,
                                                @Nullable NonceClaimValidator nonceClaimValidator,
                                                @NonNull JsonWebTokenParser<JWT> jsonWebTokenParser,
                                                @NonNull JwkValidator jwkValidator,
                                                @NonNull JwkSetFetcher<JWKSet> jwkSetFetcher) {
        this.openIdClaimsValidators = idTokenValidators;
        this.genericJwtClaimsValidators = genericJwtClaimsValidators;
        this.nonceClaimValidator = nonceClaimValidator;
        this.jsonWebTokenParser = jsonWebTokenParser;
        this.jwkValidator = jwkValidator;
        this.jwkSetFetcher = jwkSetFetcher;
    }

    @Override
    @NonNull
    @SingleResult
    public Publisher<JWT> validate(@NonNull OauthClientConfiguration clientConfiguration,
                                   @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                   @NonNull OpenIdTokenResponse openIdTokenResponse,
                                   @Nullable String nonce) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Validating the JWT signature using the JWKS uri [{}]", openIdProviderMetadata.getJwksUri());
        }
        HttpRequest<?> request = ServerRequestContext.currentRequest().orElse(null);
        Optional<JWT> jwtOptional = jsonWebTokenParser.parse(openIdTokenResponse.getIdToken());
        if (jwtOptional.isEmpty()) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to parse the ID token returned from provider [{}]", clientConfiguration.getName());
            }
            return Mono.empty();
        }
        JWT jwt = jwtOptional.get();
        if (!(jwt instanceof SignedJWT signedJwt)) {
            if (LOG.isErrorEnabled()) {
                LOG.error("The ID token returned from provider [{}] is not a signed JWT", clientConfiguration.getName());
            }
            return Mono.empty();
        }
        return Mono.from(jwksSignatureForOpenIdProviderMetadata(openIdProviderMetadata).verify(signedJwt))
                .filter(Boolean::booleanValue)
                .switchIfEmpty(Mono.defer(() -> {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("JWT signature validation failed for provider [{}]", clientConfiguration.getName());
                    }
                    return Mono.empty();
                }))
                .map(verified -> jwt)
                .filter(verifiedJwt -> validateClaims(clientConfiguration, openIdProviderMetadata, verifiedJwt, nonce, request));
    }

    /**
     * @param openIdProviderMetadata The OpenID provider metadata
     * @return A signature configuration backed by the JSON Web Key Set published by the OpenID provider
     */
    @NonNull
    private ReactiveSignatureConfiguration<SignedJWT> jwksSignatureForOpenIdProviderMetadata(@NonNull OpenIdProviderMetadata openIdProviderMetadata) {
        return jwksSignatures.computeIfAbsent(new JwksKey(openIdProviderMetadata.getName(), openIdProviderMetadata.getJwksUri()), key -> {
            JwksSignatureConfigurationProperties jwksSignatureConfiguration = new JwksSignatureConfigurationProperties(key.providerName());
            jwksSignatureConfiguration.setUrl(key.jwksUri());
            return new ReactiveJwksSignature(jwksSignatureConfiguration, jwkValidator, jwkSetFetcher);
        });
    }

    /**
     *
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param jwt JWT with valida signature
     * @param nonce The persisted nonce value
     * @param request The current request, if any
     * @return the same JWT supplied as a parameter if the claims validation were succesful or empty if not.
     */
    @NonNull
    private boolean validateClaims(@NonNull OauthClientConfiguration clientConfiguration,
                                   @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                   @NonNull JWT jwt,
                                   @Nullable String nonce,
                                   @Nullable HttpRequest<?> request) {
        try {
            JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
            OpenIdClaims claims = new JWTOpenIdClaims(claimsSet);
            if (genericJwtClaimsValidators.stream().allMatch(validator -> validator.validate(claims, request))) {
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
                        LOG.error("Nonce validation failed for provider [{}]", clientConfiguration.getName());
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
     * The provider name selects service-specific HTTP client settings, so it is part of the cache key.
     *
     * @param providerName The OpenID provider name
     * @param jwksUri The JSON Web Key Set URI
     */
    private record JwksKey(String providerName, String jwksUri) {
    }
}
