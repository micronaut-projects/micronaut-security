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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.token.Claims;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validate JWT subject claim is not null.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
@Requires(property = JwtClaimsValidatorConfigurationProperties.PREFIX + ".subject-not-null", notEquals = StringUtils.FALSE)
public class SubjectNotNullJwtClaimsValidator implements GenericJwtClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(SubjectNotNullJwtClaimsValidator.class);

    /**
     *
     * @param claimsSet JWT Claims
     * @return True if the JWT subject claim is not null
     */
    public boolean validate(JWTClaimsSet claimsSet) {
        final String subject = claimsSet.getSubject();
        boolean hasSubject = subject != null;
        if (!hasSubject && LOG.isDebugEnabled()) {
            LOG.debug("JWT must contain a subject ('sub' claim)");
        }
        return hasSubject;
    }

    @Override
    public boolean validate(@NonNull Claims claims, @Nullable HttpRequest<?> request) {
        return validate(JWTClaimsSetUtils.jwtClaimsSetFromClaims(claims));
    }
}
