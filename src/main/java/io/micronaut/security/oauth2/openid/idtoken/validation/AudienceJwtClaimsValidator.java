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
import io.micronaut.security.token.jwt.validator.JwtClaimsValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.List;

/**
 * ID Token Audience validator.
 *
 * The Client MUST validate that the aud (audience) Claim contains its client_id value registered at the Issuer identified by the iss (issuer) Claim as an audience. The aud (audience) Claim MAY contain an array with more than one element. The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience, or if it contains additional audiences not trusted by the Client.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation OpenID Connect Core Spec</a>
 * @since 1.0.0
 * @author Sergio del Amo
 */
@Requires(property = JwtClaimsValidator.PREFIX + ".audience", notEquals = StringUtils.FALSE)
@Requires(beans = OauthConfiguration.class)
@Singleton
public class AudienceJwtClaimsValidator implements IdTokenClaimsValidator {
    private static final Logger LOG = LoggerFactory.getLogger(AudienceJwtClaimsValidator.class);

    @Nonnull
    private final OauthConfiguration oauthConfiguration;

    /**
     *
     * @param oauthConfiguration Oauth Configuration.
     */
    public AudienceJwtClaimsValidator(@Nonnull OauthConfiguration oauthConfiguration) {
        this.oauthConfiguration = oauthConfiguration;
    }

    @Override
    public boolean validate(JWTClaimsSet claimsSet) {
        List<String> audienceList = claimsSet.getAudience();
        boolean condition = audienceList.stream().anyMatch(audience -> audience.equals(oauthConfiguration.getClientId()));
        if (!condition && LOG.isDebugEnabled()) {
            LOG.debug("JWT audience claims does not contain {}", oauthConfiguration.getClientId());
        }
        return condition;
    }
}
