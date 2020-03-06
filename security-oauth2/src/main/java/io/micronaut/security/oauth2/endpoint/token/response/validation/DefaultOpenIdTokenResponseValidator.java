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
package io.micronaut.security.oauth2.endpoint.token.response.validation;


import javax.annotation.Nullable;
import javax.inject.Singleton;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collection;
import java.util.Optional;

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

    /**
     * @param idTokenValidators OpenID JWT claim validators
     * @param genericJwtClaimsValidators Generic JWT claim validators
     * @param nonceClaimValidator The nonce claim validator
     * @param jwkValidator The JWK validator
     */
    public DefaultOpenIdTokenResponseValidator(Collection<OpenIdClaimsValidator> idTokenValidators,
                                               Collection<GenericJwtClaimsValidator> genericJwtClaimsValidators,
                                               NonceClaimValidator nonceClaimValidator,
                                               JwkValidator jwkValidator) {
        this.openIdClaimsValidators = idTokenValidators;
        this.genericJwtClaimsValidators = genericJwtClaimsValidators;
        this.nonceClaimValidator = nonceClaimValidator;
        this.jwkValidator = jwkValidator;
    }

    @Override
    public Optional<JWT> validate(OauthClientConfiguration clientConfiguration,
                                  OpenIdProviderMetadata openIdProviderMetadata,
                                  OpenIdTokenResponse openIdTokenResponse,
                                  @Nullable String nonce) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Validating the JWT signature using the JWKS uri [{}]", openIdProviderMetadata.getJwksUri());
        }
        Optional<JWT> jwt = JwtValidator.builder()
                .withSignatures(new JwksSignature(openIdProviderMetadata.getJwksUri(), null, jwkValidator))
                .build()
                .validate(openIdTokenResponse.getIdToken());

        if (jwt.isPresent()) {
            try {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("JWT signature validation succeeded. Validating claims...");
                }
                JWTClaimsSet claimsSet = jwt.get().getJWTClaimsSet();
                OpenIdClaims claims = new JWTOpenIdClaims(claimsSet);

                if (genericJwtClaimsValidators.stream().allMatch(validator -> validator.validate(claims))) {
                    if (openIdClaimsValidators.stream().allMatch(validator ->
                            validator.validate(claims, clientConfiguration, openIdProviderMetadata))) {
                        if (nonceClaimValidator.validate(claims, clientConfiguration, openIdProviderMetadata, nonce)) {
                            return jwt;
                        }
                    } else {
                        if (LOG.isErrorEnabled()) {
                            LOG.error("JWT OpenID specific claims validation failed for provider [{}]", clientConfiguration.getName());
                        }
                    }
                } else {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("JWT generic claims validation failed for provider [{}]", clientConfiguration.getName());
                    }
                }
            } catch (ParseException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Failed to parse the JWT returned from provider [{}]", clientConfiguration.getName(), e);
                }
            }
        } else {
            if (LOG.isErrorEnabled()) {
                LOG.error("JWT signature validation failed for provider [{}]", clientConfiguration.getName());
            }
        }
        return Optional.empty();
    }

}
