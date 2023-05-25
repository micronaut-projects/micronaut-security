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
package io.micronaut.security.oauth2.endpoint.token.response;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.AuthenticationModeConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdAdditionalClaimsConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.token.Claims;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The default implementation of {@link OpenIdAuthenticationMapper} that uses
 * the subject claim for the username and populates the attributes with the
 * non JWT standard claims. If an {@link OpenIdAuthenticationMapper} bean is created
 * with a named qualifier that is the same name of the provider, that bean will
 * be used instead of this one.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
@Requires(configuration = "io.micronaut.security.token.jwt")
public class DefaultOpenIdAuthenticationMapper implements OpenIdAuthenticationMapper {

    private final OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration;
    private final AuthenticationModeConfiguration authenticationModeConfiguration;

    /**
     * Default constructor.
     *  @param openIdAdditionalClaimsConfiguration The additional claims configuration
     * @param authenticationModeConfiguration Authentication Mode Configuration
     */
    public DefaultOpenIdAuthenticationMapper(OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration,
                                             AuthenticationModeConfiguration authenticationModeConfiguration) {
        this.openIdAdditionalClaimsConfiguration = openIdAdditionalClaimsConfiguration;
        this.authenticationModeConfiguration = authenticationModeConfiguration;
    }

    @NonNull
    @Override
    public Publisher<AuthenticationResponse> createAuthenticationResponse(String providerName,
                                                                         OpenIdTokenResponse tokenResponse,
                                                                         OpenIdClaims openIdClaims,
                                                                         @Nullable State state) {
        Map<String, Object> claims = buildAttributes(providerName, tokenResponse, openIdClaims);
        List<String> roles = getRoles(providerName, tokenResponse, openIdClaims);
        String username = getUsername(providerName, tokenResponse, openIdClaims);
        return Flux.just(AuthenticationResponse.success(username, roles, claims));
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The attributes to set in the {@link io.micronaut.security.authentication.Authentication}
     */
    protected Map<String, Object> buildAttributes(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        Map<String, Object> claims = new HashMap<>(openIdClaims.getClaims());
        Claims.ALL_CLAIMS.forEach(claims::remove);
        claims.put(OauthAuthenticationMapper.PROVIDER_KEY, providerName);
        boolean idtokenAuthentication = authenticationModeConfiguration.getAuthentication() != null && authenticationModeConfiguration.getAuthentication() == AuthenticationMode.IDTOKEN;
        if (idtokenAuthentication || openIdAdditionalClaimsConfiguration.isJwt()) {
            claims.put(OpenIdAuthenticationMapper.OPENID_TOKEN_KEY, tokenResponse.getIdToken());
        }
        if (idtokenAuthentication || openIdAdditionalClaimsConfiguration.isAccessToken()) {
            claims.put(OauthAuthenticationMapper.ACCESS_TOKEN_KEY, tokenResponse.getAccessToken());
        }
        if (idtokenAuthentication || openIdAdditionalClaimsConfiguration.isRefreshToken() && tokenResponse.getRefreshToken() != null) {
            claims.put(OauthAuthenticationMapper.REFRESH_TOKEN_KEY, tokenResponse.getRefreshToken());
        }
        return claims;
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The roles to set in the {@link io.micronaut.security.authentication.Authentication}
     */
    protected List<String> getRoles(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        return Collections.emptyList();
    }

    /**
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The username to set in the {{@link io.micronaut.security.authentication.Authentication}
     */
    protected String getUsername(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        return openIdClaims.getSubject();
    }

}
