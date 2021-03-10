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

import java.util.List;

import javax.inject.Singleton;

import com.nimbusds.jwt.JWTClaimsSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Validates JWT audience claim contains a configured value.
 *
 * @author Jason Schindler
 * @since 2.4.0
 */
@Singleton
@Requires(property = AudienceJwtClaimsValidator.AUDIENCE_PROP)
public class AudienceJwtClaimsValidator implements GenericJwtClaimsValidator {

    public static final String AUDIENCE_PROP = JwtClaimsValidator.PREFIX + ".audience";

    private static final Logger LOG = LoggerFactory.getLogger(AudienceJwtClaimsValidator.class);

    private final String expectedAudience;

    public AudienceJwtClaimsValidator(
        @Property(name = AudienceJwtClaimsValidator.AUDIENCE_PROP) String expectedAudience
    ) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing AudienceJwtClaimsValidator with audience: {}", expectedAudience);
        }
        this.expectedAudience = expectedAudience;
    }

    /**
     *
     * @param claimsSet JWT Claims
     * @return True if the JWT audience claim contains the expected value
     */
    protected boolean validate(JWTClaimsSet claimsSet) {
        final List<String> audience = claimsSet.getAudience();

        final boolean result = audience != null && audience.contains(expectedAudience);

        if (!result && LOG.isTraceEnabled()) {
            LOG.trace("Expected JWT audience claim to include '{}', but it did not.", expectedAudience);
        }

        return result;
    }

    /**
     *
     * @param claims JwtClaims
     * @return True if the JWT audience claim contains the expected value
     */
    @Deprecated
    @Override
    public boolean validate(JwtClaims claims) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }

}
