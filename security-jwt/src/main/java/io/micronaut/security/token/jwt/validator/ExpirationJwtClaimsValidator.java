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
package io.micronaut.security.token.jwt.validator;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.time.Duration;
import java.util.Date;

/**
 * Validate JWT is not expired.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 * @param <T> Request
 */
@Singleton
@Requires(property = JwtClaimsValidatorConfigurationProperties.PREFIX + ".expiration", notEquals = StringUtils.FALSE)
public class ExpirationJwtClaimsValidator<T> implements GenericJwtClaimsValidator<T> {

    private static final Logger LOG = LoggerFactory.getLogger(ExpirationJwtClaimsValidator.class);

    private final Duration clockSkew;

    /**
     * Constructor without clock skew tolerance.
     *
     * @deprecated Use {@link #ExpirationJwtClaimsValidator(JwtClaimsValidatorConfiguration)} instead.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    public ExpirationJwtClaimsValidator() {
        this.clockSkew = Duration.ZERO;
    }

    /**
     *
     * @param jwtClaimsValidatorConfiguration JWT Claims Validator Configuration
     * @since 5.4.0
     */
    @Inject
    public ExpirationJwtClaimsValidator(@NonNull JwtClaimsValidatorConfiguration jwtClaimsValidatorConfiguration) {
        Duration skew = jwtClaimsValidatorConfiguration.getClockSkew();
        this.clockSkew = skew == null || skew.isNegative() ? Duration.ZERO : skew;
    }

    /**
     *
     * @param claimsSet The JWT Claims
     * @return true if the expiration claim plus the configured clock skew denotes a date after now.
     */
    protected boolean validate(@NonNull JWTClaimsSet claimsSet) {
        final Date expTime = claimsSet.getExpirationTime();
        if (expTime != null) {
            final Date now = new Date();
            final Date expTimeWithSkew = new Date(expTime.getTime() + clockSkew.toMillis());
            if (expTimeWithSkew.before(now)) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("JWT token has expired");
                }
                return false;
            }
        }
        return true;
    }

    @Override
    public boolean validate(@NonNull Claims claims, @Nullable T request) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }
}
