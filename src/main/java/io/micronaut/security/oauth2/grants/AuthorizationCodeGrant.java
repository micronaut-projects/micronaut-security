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

package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

/**
 * Authorization Code Grant Request.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class AuthorizationCodeGrant {
    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_CLIENT_ID = "client_id";
    public static final String KEY_CLIENT_SECRET = "client_secret";
    public static final String KEY_REDIRECT_URI = "redirect_uri";
    public static final String KEY_CODE = "code";

    @Nonnull
    @JsonProperty(KEY_GRANT_TYPE)
    private String grantType = GrantType.AUTHORIZATION_CODE.getGrantType();

    @Nonnull
    @JsonProperty(KEY_CLIENT_ID)
    private String clientId;

    @Nullable
    @JsonProperty(KEY_CLIENT_SECRET)
    private String clientSecret;

    @Nonnull
    @JsonProperty(KEY_REDIRECT_URI)
    private String redirectUri;

    @Nonnull
    private String code;

    /**
     * Instantiate Authorization Grant.
     */
    public AuthorizationCodeGrant() {

    }

    /**
     *
     * @return Oauth 2.0 Grant Type.
     */
    @Nonnull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType Oauth 2.0 Grant Type.
     */
    public void setGrantType(@Nonnull String grantType) {
        this.grantType = grantType;
    }

    /**
     *
     * @return The application's Client identifier.
     */
    @Nonnull
    public String getClientId() {
        return clientId;
    }

    /**
     *
     * @param clientId Application's Client identifier.
     */
    public void setClientId(@Nonnull String clientId) {
        this.clientId = clientId;
    }

    /**
     *
     * @param clientSecret Application's Client clientSecret.
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    /**
     *
     * @return The application's Client clientSecret.
     */
    public String getClientSecret() {
        return this.clientSecret;
    }

    /**
     *
     * @return Redirection URI to which the response will be sent.
     */
    @Nonnull
    public String getRedirectUri() {
        return redirectUri;
    }

    /**
     *
     * @param redirectUri Redirection URI to which the response will be sent.
     */
    public void setRedirectUri(@Nonnull String redirectUri) {
        this.redirectUri = redirectUri;
    }

    /**
     *
     * @return An authorization code.
     */
    @Nonnull
    public String getCode() {
        return code;
    }

    /**
     *
     * @param code An authorization code.
     */
    public void setCode(@Nonnull String code) {
        this.code = code;
    }

    /**
     *
     * @return this object as a Map
     */
    public Map<String, String> toMap() {
        Map<String, String> m = new HashMap<>(5);
        m.put(KEY_GRANT_TYPE, getGrantType());
        m.put(KEY_CLIENT_ID, getClientId());
        if (getClientSecret() != null) {
            m.put(KEY_CLIENT_SECRET, getClientSecret());
        }
        m.put(KEY_REDIRECT_URI, getRedirectUri());
        m.put(KEY_CODE, getCode());
        return m;
    }
}
