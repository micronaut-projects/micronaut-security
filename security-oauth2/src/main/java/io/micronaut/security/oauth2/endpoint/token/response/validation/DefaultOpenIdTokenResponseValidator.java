/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.endpoint.token.response.validation;


import javax.annotation.Nullable;
import javax.inject.Named;
import javax.inject.Singleton;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.JWTOpenIdClaims;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.signature.jwks.JwkValidator;
import io.micronaut.security.token.jwt.signature.jwks.JwksSignature;
import io.micronaut.security.token.jwt.validator.GenericJwtClaimsValidator;
import io.micronaut.security.token.jwt.validator.JwtTokenValidatorUtils;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

/**
 * Default implementation of {@link OpenIdTokenResponseValidator}.
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Named("claimsvalidator")
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
    public Publisher<Boolean> validate(OauthClientConfiguration clientConfiguration,
                                       OpenIdProviderMetadata openIdProviderMetadata,
                                       String token,
                                       @Nullable String nonce) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Validating the JWT signature using the JWKS uri [{}]", openIdProviderMetadata.getJwksUri());
        }
        Optional<JWT> jwt = JwtTokenValidatorUtils.parseJwtIfValidSignature(token,
                Collections.singletonList(new JwksSignature(openIdProviderMetadata.getJwksUri(), null, jwkValidator)),
                Collections.emptyList());

        if (!jwt.isPresent()) {
            if (LOG.isErrorEnabled()) {
                LOG.error("JWT signature validation failed for provider [{}]", clientConfiguration.getName());
            }
            return Flowable.just(false);
        }
        try {
            if (LOG.isTraceEnabled()) {
                LOG.trace("JWT signature validation succeeded. Validating claims...");
            }
            JWTClaimsSet claimsSet = jwt.get().getJWTClaimsSet();
            OpenIdClaims claims = new JWTOpenIdClaims(claimsSet);

            if (!genericJwtClaimsValidators.stream().allMatch(validator -> validator.validate(claims))) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("JWT generic claims validation failed for provider [{}]", clientConfiguration.getName());
                }
                return Flowable.just(false);
            }
            if (!openIdClaimsValidators.stream().allMatch(validator ->
                validator.validate(claims, clientConfiguration, openIdProviderMetadata))) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("JWT OpenID specific claims validation failed for provider [{}]", clientConfiguration.getName());
                }
                return Flowable.just(false);
            }
            return Flowable.just(nonceClaimValidator.validate(claims, clientConfiguration, openIdProviderMetadata, nonce));

        } catch (ParseException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to parse the JWT returned from provider [{}]", clientConfiguration.getName(), e);
            }
        }
        return Flowable.just(false);
    }

}
