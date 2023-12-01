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

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.token.jwt.signature.jwks.JwkSetFetcher;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignatureConfigurationProperties;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Default implementation of {@link OpenIdTokenResponseValidator}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Singleton
public class DefaultOpenIdTokenResponseValidator implements OpenIdTokenResponseValidator {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdTokenResponseValidator.class);

    private final Collection<OpenIdClaimsValidator> openIdClaimsValidators;
    private final Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators;
    private final NonceClaimValidator nonceClaimValidator;
    private final JwkValidator jwkValidator;
    private final Map<String, JwksSignature> jwksSignatures = new ConcurrentHashMap<>();
    private final JwkSetFetcher<JWKSet> jwkSetFetcher;

    /**
     * @param idTokenValidators OpenID JWT claim validators
     * @param genericJwtClaimsValidators Generic JWT claim validators
     * @param nonceClaimValidator The nonce claim validator
     * @param jwkValidator The JWK validator
     * @param jwkSetFetcher Json Web Key Set Fetcher
     */
    public DefaultOpenIdTokenResponseValidator(Collection<OpenIdClaimsValidator> idTokenValidators,
                                               Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                                               @Nullable NonceClaimValidator nonceClaimValidator,
                                               JwkValidator jwkValidator,
                                               JwkSetFetcher<JWKSet> jwkSetFetcher) {
        this.openIdClaimsValidators = idTokenValidators;
        this.genericJwtClaimsValidators = genericJwtClaimsValidators;
        this.nonceClaimValidator = nonceClaimValidator;
        this.jwkValidator = jwkValidator;
        this.jwkSetFetcher = jwkSetFetcher;
    }

    @Override
    public Optional<JWT> validate(OauthClientConfiguration clientConfiguration,
                                  OpenIdProviderMetadata openIdProviderMetadata,
                                  OpenIdTokenResponse openIdTokenResponse,
                                  @Nullable String nonce) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Validating the JWT signature using the JWKS uri [{}]", openIdProviderMetadata.getJwksUri());
        }
        Optional<JWT> jwt = parseJwtWithValidSignature(clientConfiguration, openIdProviderMetadata, openIdTokenResponse);

        if (jwt.isPresent()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("JWT signature validation succeeded. Validating claims...");
            }
            return validateClaims(clientConfiguration, openIdProviderMetadata, jwt.get(), nonce);
        } else {
            if (LOG.isErrorEnabled()) {
                LOG.error("JWT signature validation failed for provider [{}]", clientConfiguration.getName());
            }
        }
        return Optional.empty();
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
    protected Optional<JWT> validateClaims(@NonNull OauthClientConfiguration clientConfiguration,
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
                        return Optional.of(jwt);
                    }
                    if (nonceClaimValidator.validate(claims, clientConfiguration, openIdProviderMetadata, nonce)) {
                        return Optional.of(jwt);
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
        return Optional.empty();
    }

    /**
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * Uses the ID token in the OpenID connect response to extract a JSON Web token and validates its signature
     * @return A JWT if the signature validation is successful
     * @deprecated Use {@link #parseJwtWithValidSignature} instead.
     */
    @NonNull
    @Deprecated(since = "4.5.0", forRemoval = true)
    protected Optional<JWT> parseJwtWithValidSignature(@NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                                       @NonNull OpenIdTokenResponse openIdTokenResponse) {

        return parseJwtWithValidSignature(null, openIdProviderMetadata, openIdTokenResponse);
    }

    /**
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @param openIdTokenResponse ID Token Access Token response
     * Uses the ID token in the OpenID connect response to extract a JSON Web token and validates its signature
     * @return A JWT if the signature validation is successful
     */
    @NonNull
    protected Optional<JWT> parseJwtWithValidSignature(@NonNull OauthClientConfiguration clientConfiguration,
                                                       @NonNull OpenIdProviderMetadata openIdProviderMetadata,
                                                       @NonNull OpenIdTokenResponse openIdTokenResponse) {

        return JwtValidator.builder()
                .withSignatures(jwksSignatureForOpenIdProviderMetadata(clientConfiguration, openIdProviderMetadata))
                .build()
                .validate(openIdTokenResponse.getIdToken(), null);
    }

    /**
     * @param openIdProviderMetadata The OpenID provider metadata
     * @return A {@link JwksSignature} for the OpenID provider JWKS uri.
     * @deprecated Use {@link #jwksSignatureForOpenIdProviderMetadata(OauthClientConfiguration, OpenIdProviderMetadata)} instead.
     */
    @Deprecated(since = "4.5.0", forRemoval = true)
    protected JwksSignature jwksSignatureForOpenIdProviderMetadata(@NonNull OpenIdProviderMetadata openIdProviderMetadata) {
        return jwksSignatureForOpenIdProviderMetadata(null, openIdProviderMetadata);
    }

    /**
     * @param clientConfiguration The OAuth 2.0 client configuration
     * @param openIdProviderMetadata The OpenID provider metadata
     * @return A {@link JwksSignature} for the OpenID provider JWKS uri.
     */
    protected JwksSignature jwksSignatureForOpenIdProviderMetadata(@Nullable OauthClientConfiguration clientConfiguration,
                                                                   @NonNull OpenIdProviderMetadata openIdProviderMetadata) {
        final String jwksUri = openIdProviderMetadata.getJwksUri();
        jwksSignatures.computeIfAbsent(jwksUri, k -> {
            String providerName = clientConfiguration != null ? clientConfiguration.getName() : null;
            JwksSignatureConfigurationProperties config = new JwksSignatureConfigurationProperties(providerName);
            config.setUrl(jwksUri);
            return new JwksSignature(config, jwkValidator, jwkSetFetcher);
        });
        return jwksSignatures.get(jwksUri);
    }
}
