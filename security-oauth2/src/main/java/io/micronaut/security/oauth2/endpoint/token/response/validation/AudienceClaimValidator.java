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

package io.micronaut.security.oauth2.endpoint.token.response.validation;

import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.client.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.endpoint.token.response.OpenIdClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.List;

/**
 * ID Token Audience validator.
 *
 * The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation OpenID Connect Core Spec</a>
 * @since 1.2.0
 * @author Sergio del Amo
 */
@Singleton
public class AudienceClaimValidator implements OpenIdClaimsValidator {

    private static final Logger LOG = LoggerFactory.getLogger(AudienceClaimValidator.class);

    @Override
    public boolean validate(OpenIdClaims claims,
                            OauthClientConfiguration clientConfiguration,
                            OpenIdProviderMetadata providerMetadata) {
        List<String> audienceList = claims.getAudience();

        //The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience.
        boolean condition = audienceList.stream().anyMatch(audience -> audience.equals(clientConfiguration.getClientId()));
        if (!condition && LOG.isTraceEnabled()) {
            LOG.trace("JWT validation failed for provider [{}]. Audience claims does not contain [{}]", clientConfiguration.getName(), clientConfiguration.getClientId());
        }

        //If the ID Token contains multiple audiences, the Client SHOULD verify that an azp Claim is present.
        if (audienceList.size() > 1) {
            condition = claims.getAuthorizedParty() != null;
            if (!condition && LOG.isTraceEnabled()) {
                LOG.trace("JWT validation failed for provider [{}]. Multiple audience claims present but no authorized party", clientConfiguration.getName());
            }
        }

        return condition;
    }

}
