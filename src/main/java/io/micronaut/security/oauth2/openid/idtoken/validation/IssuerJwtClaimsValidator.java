/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.security.oauth2.openid.idtoken.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata;
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Singleton;

/**
 * The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
 *
 * @see <a href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata">Open ID Provider Metadata Spec</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation - OpenID Connect Core Spec</a>
 * @since 1.0.0
 * @author Sergio del Amo
 */
@Requires(property = JwtClaimsValidator.PREFIX + ".issuer", notEquals = StringUtils.FALSE)
@Requires(beans = OauthConfiguration.class)
@Singleton
public class IssuerJwtClaimsValidator implements IdTokenClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(IssuerJwtClaimsValidator.class);

    @Nonnull
    private final OpenIdProviderMetadata openIdProviderMetadata;

    /**
     *
     * @param openIdProviderMetadata OpenID provider metadata.
     */
    public IssuerJwtClaimsValidator(@Nonnull OpenIdProviderMetadata openIdProviderMetadata) {
        this.openIdProviderMetadata = openIdProviderMetadata;
    }

    @Override
    public boolean validate(JWTClaimsSet claimsSet) {
        String issuer = claimsSet.getIssuer();
        if (issuer == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("issue claims does not exist");
            }
            return false;
        }

        boolean condition = issuer.equals(openIdProviderMetadata.getIssuer());
        if (!condition && LOG.isDebugEnabled()) {
            LOG.debug("JWT issuer claim does not match {}", openIdProviderMetadata.getIssuer());
        }
        return condition;
    }
}
