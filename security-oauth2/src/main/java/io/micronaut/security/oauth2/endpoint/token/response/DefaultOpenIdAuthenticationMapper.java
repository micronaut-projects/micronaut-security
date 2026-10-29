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
import io.micronaut.core.util.SupplierUtil;
import io.micronaut.security.authentication.AuthenticationMode;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.AuthenticationModeConfiguration;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdAdditionalClaimsConfiguration;
import io.micronaut.security.oauth2.configuration.OpenIdConfiguration;
import io.micronaut.security.oauth2.endpoint.authorization.state.State;
import io.micronaut.security.oauth2.grants.GrantType;
import io.micronaut.security.token.Claims;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The default implementation of {@link OpenIdAuthenticationMapper} that uses
 * the subject claim for the username and populates the attributes with the
 * non JWT standard claims. If an {@link OpenIdAuthenticationMapper} bean is created
 * with a named qualifier that is the same name of the provider, that bean will
 * be used instead of this one.
 * <p>
 * The {@code sub} claim is only unique within the provider which issued it. When more than one enabled OAuth 2.0 client
 * (other than client-credentials-only clients) is configured under {@code micronaut.security.oauth2.clients}, or when
 * {@code micronaut.security.oauth2.openid.qualify-username-with-provider} is {@code true}, the username is qualified
 * with the provider name as {@code providerName:subject} so that users of different providers who share a
 * {@code sub} do not resolve to the same user. This is the same convention the UserInfo endpoint token validator uses.
 * The unqualified subject remains available in the {@code sub} attribute. Note that with
 * {@code micronaut.security.authentication} set to {@code idtoken} the ID token itself is the credential of later
 * requests, so their username is the bare {@code sub} claim and is not qualified.
 *
 * @author James Kleeh
 * @since 1.2.0
 */
@Singleton
@Requires(configuration = "io.micronaut.security.token.jwt")
public class DefaultOpenIdAuthenticationMapper implements OpenIdAuthenticationMapper {

    /**
     * Separator between the provider name and the {@code sub} claim in a qualified username.
     * @since 4.18.2
     */
    public static final String PROVIDER_USERNAME_SEPARATOR = ":";

    private final OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration;
    private final AuthenticationModeConfiguration authenticationModeConfiguration;
    private final Supplier<Boolean> qualifyUsernameWithProvider;

    /**
     * Default constructor.
     *  @param openIdAdditionalClaimsConfiguration The additional claims configuration
     * @param authenticationModeConfiguration Authentication Mode Configuration
     * @deprecated Use {@link #DefaultOpenIdAuthenticationMapper(OpenIdAdditionalClaimsConfiguration, AuthenticationModeConfiguration, OpenIdConfiguration, Collection)} instead. This constructor never qualifies the username with the provider name.
     */
    @Deprecated(forRemoval = true, since = "4.18.2")
    public DefaultOpenIdAuthenticationMapper(OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration,
                                             AuthenticationModeConfiguration authenticationModeConfiguration) {
        this(openIdAdditionalClaimsConfiguration, authenticationModeConfiguration, null, Collections.emptyList());
    }

    /**
     * @param openIdAdditionalClaimsConfiguration The additional claims configuration
     * @param authenticationModeConfiguration Authentication Mode Configuration
     * @param openIdConfiguration OpenID configuration
     * @param oauthClientConfigurations The OAuth 2.0 client configurations
     * @since 4.18.2
     */
    @Inject
    public DefaultOpenIdAuthenticationMapper(OpenIdAdditionalClaimsConfiguration openIdAdditionalClaimsConfiguration,
                                             AuthenticationModeConfiguration authenticationModeConfiguration,
                                             @Nullable OpenIdConfiguration openIdConfiguration,
                                             Collection<OauthClientConfiguration> oauthClientConfigurations) {
        this.openIdAdditionalClaimsConfiguration = openIdAdditionalClaimsConfiguration;
        this.authenticationModeConfiguration = authenticationModeConfiguration;
        this.qualifyUsernameWithProvider = SupplierUtil.memoized(() -> {
            Boolean configured = openIdConfiguration == null ? null : openIdConfiguration.getQualifyUsernameWithProvider().orElse(null);
            if (configured != null) {
                return configured;
            }
            return oauthClientConfigurations.stream()
                .filter(OauthClientConfiguration::isEnabled)
                .filter(c -> c.getGrantType() != GrantType.CLIENT_CREDENTIALS)
                .count() > 1;
        });
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
        if (isQualifyUsernameWithProvider() && openIdClaims.getSubject() != null) {
            // ALL_CLAIMS were removed, keep the unqualified subject so applications do not have to split the username
            claims.put(Claims.SUBJECT, openIdClaims.getSubject());
        }
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
     * Returns the {@code sub} claim, qualified with the provider name as {@code providerName:subject} when
     * {@link #isQualifyUsernameWithProvider()} is {@code true}.
     *
     * @param providerName The OpenID provider name
     * @param tokenResponse The token response
     * @param openIdClaims The OpenID claims
     * @return The username to set in the {{@link io.micronaut.security.authentication.Authentication}
     */
    protected String getUsername(String providerName, OpenIdTokenResponse tokenResponse, OpenIdClaims openIdClaims) {
        String subject = openIdClaims.getSubject();
        if (subject == null || !isQualifyUsernameWithProvider()) {
            return subject;
        }
        return providerName + PROVIDER_USERNAME_SEPARATOR + subject;
    }

    /**
     * Whether {@link #getUsername(String, OpenIdTokenResponse, OpenIdClaims)} qualifies the {@code sub} claim with the provider name.
     * This is the value of {@code micronaut.security.oauth2.openid.qualify-username-with-provider} if set; otherwise {@code true}
     * when more than one enabled OAuth 2.0 client, other than client-credentials-only clients, is configured under
     * {@code micronaut.security.oauth2.clients}.
     *
     * @return Whether the username is qualified with the provider name
     * @since 4.18.2
     */
    public boolean isQualifyUsernameWithProvider() {
        return qualifyUsernameWithProvider.get();
    }

}
