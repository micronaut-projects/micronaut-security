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

package io.micronaut.security.oauth2.openid.endpoints.token;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.oauth2.configuration.OauthConfiguration;
import io.micronaut.security.oauth2.grants.AuthorizationCodeGrant;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderMetadata;
import io.micronaut.security.oauth2.openid.endpoints.DefaultRedirectUrlProvider;

import javax.annotation.Nonnull;
import javax.inject.Singleton;
import java.util.Objects;

/**
 * Default implementation of {@link AuthorizationCodeGrantRequestGenerator}.
 *
 * @since 1.0.0
 * @author Sergio del Amo
 */
@Requires(beans = {OpenIdProviderMetadata.class, TokenEndpointConfiguration.class, OauthConfiguration.class})
@Requires(condition = TokenEndpointNotNullCondition.class)
@Requires(condition = TokenEndpointGrantTypeAuthorizationCodeCondition.class)
@Singleton
public class DefaultAuthorizationCodeGrantRequestGenerator implements AuthorizationCodeGrantRequestGenerator {

    @Nonnull
    private final OauthConfiguration oauthConfiguration;

    @Nonnull
    private final OpenIdProviderMetadata openIdProviderMetadata;

    @Nonnull
    private final TokenEndpointConfiguration tokenEndpointConfiguration;

    @Nonnull
    private final DefaultRedirectUrlProvider defaultRedirectUrlProvider;

    /**
     *
     * @param oauthConfiguration OAuth 2.0 Configuration
     * @param openIdProviderMetadata OpenID provider metadata.
     * @param tokenEndpointConfiguration Token Endpoint configuration
     * @param defaultRedirectUrlProvider The Default Redirect Url Provider.
     */
    public DefaultAuthorizationCodeGrantRequestGenerator(@Nonnull OauthConfiguration oauthConfiguration,
                                                         @Nonnull OpenIdProviderMetadata openIdProviderMetadata,
                                                         @Nonnull TokenEndpointConfiguration tokenEndpointConfiguration,
                                                         @Nonnull DefaultRedirectUrlProvider defaultRedirectUrlProvider) {

        this.oauthConfiguration = oauthConfiguration;
        this.openIdProviderMetadata = openIdProviderMetadata;
        this.tokenEndpointConfiguration = tokenEndpointConfiguration;
        this.defaultRedirectUrlProvider = defaultRedirectUrlProvider;
    }

    @Nonnull
    @Override
    public HttpRequest generateRequest(@Nonnull String code) {
        AuthorizationCodeGrant authorizationCodeGrant = isntantiateAuthorizationCodeGrant(code);
        Object body = tokenEndpointConfiguration.getContentType().equals(MediaType.APPLICATION_FORM_URLENCODED_TYPE) ? authorizationCodeGrant.toMap() : authorizationCodeGrant;
        MutableHttpRequest req = HttpRequest.POST(Objects.requireNonNull(openIdProviderMetadata.getTokenEndpoint()), body).header(HttpHeaders.CONTENT_TYPE, tokenEndpointConfiguration.getContentType().getName());

        return secureRequest(req);
    }

    /**
     *
     * @param request Token endpoint Request
     * @return a HTTP Request to the Token Endpoint with Authorization Code Grant payload.
     */
    protected MutableHttpRequest secureRequest(@Nonnull MutableHttpRequest request) {
        if (tokenEndpointConfiguration.getAuthMethod() != null && tokenEndpointConfiguration.getAuthMethod().equals(TokenEndpointAuthMethod.CLIENT_SECRET_BASIC.getAuthMethod())) {
            return request.basicAuth(oauthConfiguration.getClientId(), oauthConfiguration.getClientSecret());
        }
        return request;
    }

    /**
     * @param code The code received with the authentication response.
     * @return A Authorization Code Grant
     */
    protected AuthorizationCodeGrant isntantiateAuthorizationCodeGrant(@Nonnull String code) {
        AuthorizationCodeGrant authorizationCodeGrant = new AuthorizationCodeGrant();
        authorizationCodeGrant.setCode(code);
        authorizationCodeGrant.setClientId(oauthConfiguration.getClientId());
        authorizationCodeGrant.setClientSecret(oauthConfiguration.getClientSecret());
        authorizationCodeGrant.setRedirectUri(tokenEndpointConfiguration.getRedirectUri() != null ? tokenEndpointConfiguration.getRedirectUri() : defaultRedirectUrlProvider.getRedirectUri());
        return authorizationCodeGrant;
    }
}
