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

package io.micronaut.security.oauth2.openid.endpoints.authorization;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import io.micronaut.security.oauth2.openid.OpenIdScope;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.List;

/**
 * {@link ConfigurationProperties} for OAuth 2.0 authorization endpoint.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@ConfigurationProperties(AuthorizationEndpointConfigurationProperties.PREFIX)
public class AuthorizationEndpointConfigurationProperties implements AuthorizationEndpointConfiguration, AuthorizationEndpointRequestConfiguration {

    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".authorization";

    /**
     * Default response type.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_RESPONSETYPE = "code";

    /**
     * Default response mode.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_RESPONSEMODE = "query";

    /**
     * Default scope.
     */
    @SuppressWarnings("WeakerAccess")
    public static final String DEFAULT_SCOPE = OpenIdScope.OPENID.getScope();

    @Nullable
    private String url;

    @Nullable
    private String redirectUri;

    @Nonnull
    private List<String> scopes = Collections.singletonList(DEFAULT_SCOPE);

    @Nonnull
    private String responseType = DEFAULT_RESPONSETYPE;

    // This is nullable to enable users to set it to null because the Spec says "The use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type."
    @Nullable
    private String responseMode = DEFAULT_RESPONSEMODE;

    @Nullable
    private Display display;

    @Nullable
    private Prompt prompt;

    @Nullable
    private Integer maxAge;

    @Nullable
    private List<String> uiLocales;

    @Nullable
    private List<String>  acrValues;

    @Nullable
    @Override
    public String getUrl() {
        return url;
    }

    /**
     *
     * @param url the authorization endpoint's url.
     */
    public void setUrl(@Nullable String url) {
        this.url = url;
    }

    @Override
    @Nonnull
    public List<String> getScopes() {
        return scopes;
    }

    /**
     * Sets Oauth 2.0 scopes. Default value (['openid']).
     * @param scopes OAuth 2.0 scopes.
     */
    public void setScopes(@Nonnull List<String> scopes) {
        this.scopes = scopes;
    }

    @Nonnull
    @Override
    public String getResponseType() {
        return responseType;
    }

    /**
     * Set OAuth 2.0 Response Type. Default value ({@value #DEFAULT_RESPONSETYPE}).
     * @param responseType OAuth 2.0 Response Type.
     */
    public void setResponseType(@Nonnull String responseType) {
        this.responseType = responseType;
    }

    @Nullable
    @Override
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     * Redirection URI to which the response will be sent. Default value (http://localhost:8080/auth/code).
     * @param redirectUri Redirection URI to which the response will be sent.
     */
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    @Nullable
    @Override
    public String getResponseMode() {
        return responseMode;
    }

    /**
     * Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint. Default value ({@value #DEFAULT_RESPONSEMODE}).
     * @param responseMode Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.
     */
    public void setResponseMode(@Nullable String responseMode) {
        this.responseMode = responseMode;
    }

    @Nullable
    @Override
    public Display getDisplay() {
        return display;
    }

    /**
     * ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User. Default value (null).
     * @param display ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
     */
    public void setDisplay(@Nullable Display display) {
        this.display = display;
    }

    @Nullable
    @Override
    public Prompt getPrompt() {
        return prompt;
    }

    /**
     * Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent. Default value (null).
     * @param prompt Space delimited, case sensitive list of ASCII string values that specifies whether the Authorization Server prompts the End-User for reauthentication and consent.
     */
    public void setPrompt(@Nullable Prompt prompt) {
        this.prompt = prompt;
    }

    @Nullable
    @Override
    public Integer getMaxAge() {
        return maxAge;
    }

    /**
     * Maximum Authentication Age. Default value (null).
     * @param maxAge Maximum Authentication Age.
     */
    public void setMaxAge(@Nullable Integer maxAge) {
        this.maxAge = maxAge;
    }

    @Nullable
    @Override
    public List<String> getUiLocales() {
        return uiLocales;
    }

    /**
     * End-User's preferred languages and scripts for the user interface. Default value (null).
     * @param uiLocales End-User's preferred languages and scripts for the user interface
     */
    public void setUiLocales(@Nullable List<String> uiLocales) {
        this.uiLocales = uiLocales;
    }

    @Nullable
    @Override
    public List<String> getAcrValues() {
        return acrValues;
    }

    /**
     * Requested Authentication Context Class Reference values. Default value (null).
     * @param acrValues Requested Authentication Context Class Reference values.
     */
    public void setAcrValues(@Nullable List<String>  acrValues) {
        this.acrValues = acrValues;
    }
}
