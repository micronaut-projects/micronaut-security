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

import java.util.Date;

import jakarta.inject.Singleton;

import com.nimbusds.jwt.JWTClaimsSet;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.http.HttpRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

/**
 * Validate current time is not before the not-before claim of a JWT token.
 *
 * @author Jason Schindler
 * @author Sergio del Amo
 * @since 2.4.0
 */
@Singleton
@Requires(property = NotBeforeJwtClaimsValidator.NOT_BEFORE_PROP, value = StringUtils.TRUE)
public class NotBeforeJwtClaimsValidator implements GenericJwtClaimsValidator {

    public static final String NOT_BEFORE_PROP = JwtClaimsValidatorConfigurationProperties.PREFIX + ".not-before";

    private static final Logger LOG = LoggerFactory.getLogger(NotBeforeJwtClaimsValidator.class);

    /**
     *
     * @param claimsSet The JWT Claims
     * @return true if the not-before claim denotes a date before now
     */
    protected boolean validate(@NonNull JWTClaimsSet claimsSet) {
        final Date notBefore = claimsSet.getNotBeforeTime();
        if (notBefore == null) {
            return true;
        }

        final Date now = new Date();

        if (now.before(notBefore)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Invalidating JWT not-before Claim because current time ({}) is before ({}).", now, notBefore);
            }
            return false;
        }

        return true;
    }

    /**
     *
     * @param claims The JwtClaims
     * @param request HTTP Request
     * @return true if the not-before claim denotes a date before now
     */
    @Override
    public boolean validate(@NonNull JwtClaims claims, @Nullable HttpRequest<?> request) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }

}
