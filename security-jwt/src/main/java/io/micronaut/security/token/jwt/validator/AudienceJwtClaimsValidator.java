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

import jakarta.inject.Singleton;

import com.nimbusds.jwt.JWTClaimsSet;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Validates JWT audience claim contains a configured value.
 *
 * @author Jason Schindler
 * @author Sergio del Amo
 * @since 2.4.0
 */
@Singleton
@Requires(property = JwtClaimsValidatorConfigurationProperties.PREFIX + ".audience")
public class AudienceJwtClaimsValidator implements GenericJwtClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AudienceJwtClaimsValidator.class);

    @Nullable
    private final String expectedAudience;

    /**
     *
     * @param jwtClaimsValidatorConfiguration JWT Claims Validator Configuration
     */
    public AudienceJwtClaimsValidator(JwtClaimsValidatorConfiguration jwtClaimsValidatorConfiguration) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing AudienceJwtClaimsValidator with audience: {}", jwtClaimsValidatorConfiguration.getAudience());
        }
        this.expectedAudience = jwtClaimsValidatorConfiguration.getAudience();
    }

    /**
     *
     * @param claimsSet JWT Claims
     * @return True if the JWT audience claim contains the expected value
     */
    protected boolean validate(JWTClaimsSet claimsSet) {
        if (expectedAudience == null) {
            return true;
        }
        final List<String> audience = claimsSet.getAudience();
        if (audience.isEmpty()) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT audience claim {} but audience list is not specified", expectedAudience);
            }
            return false;
        }
        if (!audience.contains(expectedAudience)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT audience claim to include '{}', but audience list ({}) did not.", expectedAudience, String.join(",", audience));
            }
            return false;
        }

        return true;
    }

    @Override
    public boolean validate(@NonNull JwtClaims claims,
                            @Nullable HttpRequest<?> request) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }
}
