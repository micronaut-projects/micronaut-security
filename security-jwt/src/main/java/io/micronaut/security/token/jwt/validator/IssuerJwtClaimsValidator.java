/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.jwt.validator;

import jakarta.inject.Singleton;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Validates JWT issuer claim matches a configured value.
 *
 * @author Jason Schindler
 * @author Sergio del Amo
 * @since 2.4.0
 */
@Singleton
@Requires(property = IssuerJwtClaimsValidator.ISSUER_PROP)
public class IssuerJwtClaimsValidator implements GenericJwtClaimsValidator {

    public static final String ISSUER_PROP = JwtClaimsValidatorConfigurationProperties.PREFIX + ".issuer";

    private static final Logger LOG = LoggerFactory.getLogger(IssuerJwtClaimsValidator.class);

    @Nullable
    private final String expectedIssuer;

    /**
     *
     * @param jwtClaimsValidatorConfiguration JWT Claims Validator Configuration
     */
    public IssuerJwtClaimsValidator(JwtClaimsValidatorConfiguration jwtClaimsValidatorConfiguration) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing IssuerJwtClaimsValidator with issuer: {}", jwtClaimsValidatorConfiguration.getIssuer());
        }
        this.expectedIssuer = jwtClaimsValidatorConfiguration.getIssuer();
    }

    @Override
    public boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
        if (expectedIssuer == null) {
            return true;
        }
        Object issuerObject = claims.get(JwtClaims.ISSUER);
        if (issuerObject == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT issuer claim of '{}', but the token did not include an issuer.", expectedIssuer);
            }
            return false;
        }
        if (!expectedIssuer.equals(issuerObject.toString())) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT issuer claim of '{}', but found '{}' instead.", expectedIssuer, issuerObject.toString());
            }
            return false;
        }
        return true;
    }
}
