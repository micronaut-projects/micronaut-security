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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.oauth2.configuration.OpenIdAdditionalClaimsConfiguration;
import io.micronaut.security.token.jwt.generator.claims.JwtClaims;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The default implementation of {@link OpenIdUserDetailsMapper} that uses
 * the subject claim for the username and populates the attributes with the
 * non JWT standard claims. If an {@link OpenIdUserDetailsMapper} bean is created
 * with a named qualifier that is the same name of the provider, that bean will
 * be used instead of this one.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
@Requires(configuration = "io.micronaut.security.token.jwt")
public class DefaultOpenIdUserDetailsMapper implements OpenIdUserDetailsMapper {

    private final OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration;

    /**
     * Default constructor.
     *
     * @param openIdAdditionalClaimsConfiguration The additional claims configuration
     */
    public DefaultOpenIdUserDetailsMapper(OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration) {
        this.openIdAdditionalClaimsConfiguration = openIdAdditionalClaimsConfiguration;
    }

    @Override
    @Nonnull
    public UserDetails createUserDetails(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        Map<String, Object> claims = buildAttributes(providerName, tokenResponse, openIdClaims);
        List<String> roles = getRoles(providerName, tokenResponse, openIdClaims);
        String username = getUsername(providerName, tokenResponse, openIdClaims);
        return new UserDetails(username, roles, claims);
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The attributes to set in the {@link UserDetails}
     */
    protected Map<String, Object> buildAttributes(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        Map<String, Object> claims = new HashMap<>(openIdClaims.getClaims());
        JwtClaims.ALL_CLAIMS.forEach(claims::remove);
        claims.put(OauthUserDetailsMapper.PROVIDER_KEY, providerName);
        if (openIdAdditionalClaimsConfiguration.isJwt()) {
            claims.put(OpenIdUserDetailsMapper.OPENID_TOKEN_KEY, tokenResponse.getIdToken());
        }
        if (openIdAdditionalClaimsConfiguration.isAccessToken()) {
            claims.put(OauthUserDetailsMapper.ACCESS_TOKEN_KEY, tokenResponse.getAccessToken());
        }
        if (openIdAdditionalClaimsConfiguration.isRefreshToken() && tokenResponse.getRefreshToken() != null) {
            claims.put(OauthUserDetailsMapper.REFRESH_TOKEN_KEY, tokenResponse.getRefreshToken());
        }
        return claims;
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The roles to set in the {@link UserDetails}
     */
    protected List<String> getRoles(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        return Collections.emptyList();
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The username to set in the {@link UserDetails}
     */
    protected String getUsername(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        return openIdClaims.getSubject();
    }

}
