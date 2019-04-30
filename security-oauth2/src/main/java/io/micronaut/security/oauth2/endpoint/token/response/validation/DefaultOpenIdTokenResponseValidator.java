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

import javax.inject.Singleton;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdTokenResponse;
import io.micronaut.security.oauth2.openid.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.validator.JwtTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Collection;
import java.util.Optional;

/**
 * Default implementation of {@link OpenIdTokenResponseValidator}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Singleton
public class DefaultOpenIdTokenResponseValidator implements OpenIdTokenResponseValidator {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultOpenIdTokenResponseValidator.class);

    private final JwtTokenValidator jwtTokenValidator;
    private final Collection<OpenIdClaimsValidator> openIdClaimsValidators;

    /**
     * @param jwtTokenValidator JWT token Validator
     * @param idTokenValidators ID token JWT Claims validators
     */
    public DefaultOpenIdTokenResponseValidator(JwtTokenValidator jwtTokenValidator,
                                               Collection<OpenIdClaimsValidator> idTokenValidators) {
        this.jwtTokenValidator = jwtTokenValidator;
        this.openIdClaimsValidators = idTokenValidators;
    }

    @Override
    public Optional<JWT> validate(OauthClientConfiguration clientConfiguration,
                                  OpenIdProviderMetadata openIdProviderMetadata,
                                  OpenIdTokenResponse openIdTokenResponse) {
        Optional<JWT> jwt = jwtTokenValidator.validateJwtSignatureAndClaims(openIdTokenResponse.getIdToken());
        if (jwt.isPresent()) {
            try {
                JWTClaimsSet claimsSet = jwt.get().getJWTClaimsSet();
                if (openIdClaimsValidators.stream().allMatch(validator ->
                                validator.validate(claimsSet, clientConfiguration, openIdProviderMetadata))) {
                    return jwt;
                }
            } catch (ParseException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("Failed to parse the JWT returned from the OpenID provider [" + clientConfiguration.getName() + "]", e);
                }
            }
        }
        return Optional.empty();
    }

}
