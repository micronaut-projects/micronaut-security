/*
 * Copyright 2017-2020 original authors
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
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;

/**
 * Authorized party claim validation.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Requires(property = OauthConfigurationProperties.OpenIdConfigurationProperties.ClaimsValidationConfigurationProperties.PREFIX + ".authorized-party", notEquals = StringUtils.FALSE)
@Singleton
public class AuthorizedPartyClaimValidator implements OpenIdClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizedPartyClaimValidator.class);

    @Override
    public boolean validate(OpenIdClaims claims, OauthClientConfiguration clientConfiguration, OpenIdProviderMetadata providerMetadata) {

        //If an azp (authorized party) Claim is present, the Client SHOULD verify that its client_id is the Claim Value.
        String authorizedParty = claims.getAuthorizedParty();
        if (authorizedParty == null) {
            return true;
        }
        boolean condition = authorizedParty.equals(clientConfiguration.getClientId());
        if (!condition && LOG.isTraceEnabled()) {
            LOG.trace("JWT validation failed for provider [{}]. Authorized party claim does not match [{}]", clientConfiguration.getName(), clientConfiguration.getClientId());
        }

        return condition;
    }
}
