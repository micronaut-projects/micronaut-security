/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.micronaut.security.token.paseto.validator.claims;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.token.paseto.generator.claims.PasetoClaims;
import io.micronaut.security.token.paseto.generator.claims.PasetoClaimsSet;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

/**
 * Validate current time is not before the not-before claim of a Paseto token.
 *
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
@Requires(property = NotBeforePasetoClaimsValidator.NOT_BEFORE_PROP, value = StringUtils.TRUE)
public class NotBeforePasetoClaimsValidator implements GenericPasetoClaimsValidator {

    public static final String NOT_BEFORE_PROP = PasetoClaimsValidatorConfigurationProperties.PREFIX + ".not-before";

    private static final Logger LOG = LoggerFactory.getLogger(NotBeforePasetoClaimsValidator.class);

    /**
     * @param claimsSet The Paseto Claims
     * @return true if the not-before claim denotes a date before now
     */
    protected boolean validate(@NonNull PasetoClaimsSet claimsSet) {
        final Instant notBefore = claimsSet.getNotBeforeTime();
        if (notBefore == null) {
            return true;
        }

        final Instant now = Instant.now();

        if (now.isBefore(notBefore)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Invalidating Paseto not-before Claim because current time ({}) is before ({}).", now, notBefore);
            }
            return false;
        }

        return true;
    }

    @Override
    public boolean validate(@NonNull PasetoClaims claims, @Nullable HttpRequest<?> request) {
        return validate(PasetoClaimsSetUtils.pasetoClaimsSetFromClaims(claims));
    }
}
