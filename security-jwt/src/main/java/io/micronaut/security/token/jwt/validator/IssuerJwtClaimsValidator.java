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

import javax.inject.Singleton;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Validates JWT issuer claim matches a configured value.
 *
 * @author Jason Schindler
 * @since 2.4.0
 */
@Singleton
@Requires(property = IssuerJwtClaimsValidator.ISSUER_PROP)
public class IssuerJwtClaimsValidator implements GenericJwtClaimsValidator {

    public static final String ISSUER_PROP = JwtClaimsValidator.PREFIX + ".issuer";

    private static final Logger LOG = LoggerFactory.getLogger(IssuerJwtClaimsValidator.class);

    private final String expectedIssuer;

    public IssuerJwtClaimsValidator(
        @Property(name = IssuerJwtClaimsValidator.ISSUER_PROP) String expectedIssuer
    ) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Initializing IssuerJwtClaimsValidator with issuer: %s", expectedIssuer);
        }
        this.expectedIssuer = expectedIssuer;
    }

    /**
     *
     * @param claims JwtClaims
     * @return True if the JWT issuer claim equals the configured value
     */
    @Deprecated
    @Override
    public boolean validate(JwtClaims claims) {
        final String issuer = (String) claims.get(JwtClaims.ISSUER);

        if (issuer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Expected JWT issuer claim of '%s', but the token did not include an issuer.", expectedIssuer);
            }

            return false;
        }

        final boolean result = expectedIssuer.equals(issuer);

        if (!result && LOG.isDebugEnabled()) {
            LOG.debug("Expected JWT issuer claim of '%s', but found '%s' instead.", expectedIssuer, issuer);
        }

        return result;
    }
}
