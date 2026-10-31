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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.token.Claims;
import io.micronaut.security.token.ClaimsUtils;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates JWT issuer claim matches a configured value.
 * <p>
 * The {@code iss} claim is valid when, ignoring a leading {@code http://}/{@code https://} scheme and a trailing slash,
 * it is exactly equal to the configured issuer. Suffixes and parent domains of the configured issuer are not accepted.
 * See {@link ClaimsUtils#equalsIgnoringProtocolAndTrailingSlash(String, String)}.
 *
 * @author Jason Schindler
 * @author Sergio del Amo
 * @since 2.4.0
 * @param <T> Request
 */
@Singleton
@Requires(property = IssuerJwtClaimsValidator.ISSUER_PROP)
public class IssuerJwtClaimsValidator<T> implements GenericJwtClaimsValidator<T> {

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
        if (expectedIssuer == null || expectedIssuer.isBlank()) {
            LOG.warn("{} is set but has no value; every JWT will be rejected until it is set to the expected iss claim", ISSUER_PROP);
        }
    }

    @Override
    public boolean validate(@NonNull Claims claims, @Nullable T request) {
        if (expectedIssuer == null) {
            // the property is present (the bean exists) but bound to no value: fail closed rather than skip the validation
            if (LOG.isTraceEnabled()) {
                LOG.trace("{} has no value; rejecting the token", ISSUER_PROP);
            }
            return false;
        }
        Object issuerObject = claims.get(Claims.ISSUER);
        if (issuerObject == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT issuer claim of '{}', but the token did not include an issuer.", expectedIssuer);
            }
            return false;
        }
        if (!ClaimsUtils.equalsIgnoringProtocolAndTrailingSlash(expectedIssuer, issuerObject.toString())) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Expected JWT issuer claim of '{}', but found '{}' instead.", expectedIssuer, issuerObject);
            }
            return false;
        }
        return true;
    }
}
