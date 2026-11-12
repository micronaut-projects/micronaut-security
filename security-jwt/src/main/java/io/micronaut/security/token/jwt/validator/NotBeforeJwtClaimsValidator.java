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
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Date;

/**
 * Validate current time is not before the not-before claim of a JWT token.
 *
 * @author Jason Schindler
 * @author Sergio del Amo
 * @since 2.4.0
 * @param <T> Request
 */
@Singleton
@Requires(property = NotBeforeJwtClaimsValidator.NOT_BEFORE_PROP, value = StringUtils.TRUE)
public class NotBeforeJwtClaimsValidator<T> implements GenericJwtClaimsValidator<T> {

    public static final String NOT_BEFORE_PROP = JwtClaimsValidatorConfigurationProperties.PREFIX + ".not-before";

    private static final Logger LOG = LoggerFactory.getLogger(NotBeforeJwtClaimsValidator.class);

    private final Duration clockSkew;

    /**
     * Constructor without clock skew tolerance.
     *
     * @deprecated Use {@link #NotBeforeJwtClaimsValidator(JwtClaimsValidatorConfiguration)} instead.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    public NotBeforeJwtClaimsValidator() {
        this.clockSkew = Duration.ZERO;
    }

    /**
     *
     * @param jwtClaimsValidatorConfiguration JWT Claims Validator Configuration
     * @since 5.4.0
     */
    @Inject
    public NotBeforeJwtClaimsValidator(@NonNull JwtClaimsValidatorConfiguration jwtClaimsValidatorConfiguration) {
        Duration skew = jwtClaimsValidatorConfiguration.getClockSkew();
        this.clockSkew = skew == null || skew.isNegative() ? Duration.ZERO : skew;
    }

    /**
     *
     * @param claimsSet The JWT Claims
     * @return true if the not-before claim minus the configured clock skew denotes a date not after now
     */
    protected boolean validate(@NonNull JWTClaimsSet claimsSet) {
        final Date notBefore = claimsSet.getNotBeforeTime();
        if (notBefore == null) {
            return true;
        }

        final Date now = new Date();

        final Date notBeforeWithSkew = new Date(notBefore.getTime() - clockSkew.toMillis());
        if (notBeforeWithSkew.after(now)) {
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
    public boolean validate(@NonNull Claims claims, @Nullable T request) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }

}
