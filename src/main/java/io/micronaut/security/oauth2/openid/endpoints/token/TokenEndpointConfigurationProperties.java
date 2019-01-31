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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.http.MediaType;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.grants.GrantType;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * {@link ConfigurationProperties} implementation of {@link TokenEndpointConfiguration}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(TokenEndpointConfigurationProperties.PREFIX)
public class TokenEndpointConfigurationProperties implements TokenEndpointConfiguration {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".token";

    /**
     * Default AUTH METHOD.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_AUTHMETHOD = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC.getAuthMethod();

    /**
     * Default Grant Type.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_GRANTTYPE = GrantType.AUTHORIZATION_CODE.getGrantType();

    /**
     * Default Grant Type.
     */
    @SuppressWarnings("WeakerAccess")
    public static final MediaType DEFAULT_CONTENT_TYPE = MediaType.APPLICATION_FORM_URLENCODED_TYPE;

    @Nullable
    private String url;

    @Nonnull
    private String grantType = DEFAULT_GRANTTYPE;

    @Nullable
    private String authMethod = DEFAULT_AUTHMETHOD;

    @Nonnull
    private MediaType contentType = DEFAULT_CONTENT_TYPE;

    @Nullable
    private String redirectUri;

    @Nonnull
    @Override
    public String getGrantType() {
        return grantType;
    }

    @Nullable
    @Override
    public String getAuthMethod() {
        return authMethod;
    }

    @Nullable
    @Override
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     *
     * @param grantType Oauth 2.0 Grant Type
     */
    public void setGrantType(@Nonnull String grantType) {
        this.grantType = grantType;
    }

    /**
     *
     * @param authMethod Client Authentication method.
     */
    public void setAuthMethod(@Nullable String authMethod) {
        this.authMethod = authMethod;
    }

    /**
     *
     * @param redirectUri Redirection URI to which the response will be sent.
     */
    public void setRedirectUri(@Nullable String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Nullable
    @Override
    public String getUrl() {
        return url;
    }

    /**
     *
     * @param url token endpoint's url
     */
    public void setUrl(@Nullable String url) {
        this.url = url;
    }

    @Nonnull
    @Override
    public MediaType getContentType() {
        return this.contentType;
    }

    /**
     * The Content-Type used to communicate with the token endpoint.
     * @param contentType The Content-Type
     */
    public void setContentType(@Nonnull MediaType contentType) {
        this.contentType = contentType;
    }
}
