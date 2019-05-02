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

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashMap;
import java.util.Map;

/**
 * Password Grant Request.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class PasswordGrant implements SecureGrant, AsMap {

    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_CLIENT_ID = "client_id";
    public static final String KEY_CLIENT_SECRET = "client_secret";
    public static final String KEY_USERNAME = "username";
    public static final String KEY_PASSWORD = "password";
    public static final String KEY_SCOPE = "scope";

    private String grantType = GrantType.PASSWORD.toString();
    private String clientId;
    private String clientSecret;
    private String username;
    private String password;
    private String scope;

    /**
     * Instantiate Password Grant.
     */
    public PasswordGrant() {
    }

    /**
     * Instantiate Password Grant.
     */
    public PasswordGrant(AuthenticationRequest authenticationRequest, OauthClientConfiguration clientConfiguration) {
        username = authenticationRequest.getIdentity().toString();
        password = authenticationRequest.getSecret().toString();
        scope = clientConfiguration.getScopes().stream()
                .reduce((a, b) -> a + StringUtils.SPACE + b)
                .orElse(null);
    }

    /**
     *
     * @return OAuth 2.0 Grant Type.
     */
    @Nonnull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType OAuth 2.0 Grant Type.
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
     * @return An username
     */
    @Nonnull
    public String getUsername() {
        return username;
    }

    /**
     *
     * @param username An username
     */
    public void setUsername(@Nonnull String username) {
        this.username = username;
    }

    /**
     *
     * @return An password
     */
    @Nonnull
    public String getPassword() {
        return password;
    }

    /**
     *
     * @param password An password
     */
    public void setPassword(@Nonnull String password) {
        this.password = password;
    }

    /**
     *
     * @return Requested scopes separed by spaces
     */
    @Nullable
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope Requested scopes separed by spaces
     */
    public void setScope(@Nonnull String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return this object as a Map
     */
    public Map<String, String> toMap() {
        Map<String, String> m = new HashMap<>();
        m.put(KEY_GRANT_TYPE, grantType);
        m.put(KEY_USERNAME, username);
        m.put(KEY_PASSWORD, password);
        if (StringUtils.isNotEmpty(scope)) {
            m.put(KEY_SCOPE, scope);
        }
        if (clientId != null) {
            m.put(KEY_CLIENT_ID, clientId);
        }
        if (clientSecret != null) {
            m.put(KEY_CLIENT_SECRET, clientSecret);
        }
        return m;
    }
}

