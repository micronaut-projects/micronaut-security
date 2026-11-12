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
package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.nonce.NonceFactory;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidatorConfigurationProperties;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Responsible for validating the nonce claim.
 *
 * <p>When a {@link NonceFactory} bean is present, every authorization request sent by this library carries a
 * {@code nonce} parameter which is persisted (for example in a cookie) until the callback. In that case the persisted
 * nonce must be present at callback time and must match the {@code nonce} claim of the ID token; a missing persisted
 * nonce is treated as a validation failure, even if the ID token does not carry a {@code nonce} claim either.</p>
 *
 * <p>When no {@link NonceFactory} bean is present (for example, {@code micronaut.security.oauth2.openid.nonce.enabled}
 * is {@code false}) the authorization request does not carry a nonce, so validation passes only when neither a
 * persisted nonce nor a {@code nonce} claim exists.</p>
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(property = JwtClaimsValidatorConfigurationProperties.PREFIX + ".nonce", notEquals = StringUtils.FALSE)
@Singleton
public class NonceClaimValidator {
    private static final Logger LOG = LoggerFactory.getLogger(NonceClaimValidator.class);

    private final boolean nonceExpected;

    /**
     * Creates a validator which only checks that the persisted nonce and the nonce claim match when both are present.
     *
     * @deprecated Use {@link #NonceClaimValidator(NonceFactory)} instead.
     */
    @Deprecated(since = "5.4.0", forRemoval = true)
    public NonceClaimValidator() {
        this(null);
    }

    /**
     * @param nonceFactory The nonce factory. If present, the authorization request always carries a nonce and a
     *                     missing persisted nonce at callback time is a validation failure.
     */
    @Inject
    public NonceClaimValidator(@Nullable NonceFactory nonceFactory) {
        this.nonceExpected = nonceFactory != null;
    }

    /**
     * @param claims ID Token Claims
     * @param clientConfiguration OAuth 2.0 Client Configuration
     * @param providerMetadata OpenID Connect provider metadata
     * @param nonce The persisted nonce value
     * @return Whether the JWT Claims pass validation or not.
     */
    public boolean validate(OpenIdClaims claims,
                            OauthClientConfiguration clientConfiguration,
                            OpenIdProviderMetadata providerMetadata,
                            @Nullable String nonce) {
        String nonceClaim = claims.getNonce();
        if (nonce == null) {
            if (nonceExpected) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Nonce validation failed: a nonce was sent in the authorization request but no persisted nonce could be retrieved at callback time");
                }
                return false;
            }
            return nonceClaim == null;
        }
        return nonce.equals(nonceClaim);
    }
}
