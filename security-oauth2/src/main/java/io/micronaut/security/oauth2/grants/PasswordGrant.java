/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.oauth2.grants;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import java.util.Map;

/**
 * Resource Owner Password Credentials Grant.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.3.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.2.0
 */
@Introspected
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class PasswordGrant implements SecureGrant, AsMap {

    private static final String KEY_GRANT_TYPE = "grant_type";
    private static final String KEY_USERNAME = "username";
    private static final String KEY_PASSWORD = "password";
    private static final String KEY_SCOPE = "scope";

    private String grantType = GrantType.PASSWORD.toString();
    private String clientId;
    private String clientSecret;
    private String username;
    private String password;
    private String scope;

    /**
     * Default constructor.
     */
    public PasswordGrant() {
    }

    /**
     * @param authenticationRequest The authentication request
     * @param clientConfiguration The client configuration
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
    @NonNull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @param grantType OAuth 2.0 Grant Type.
     */
    public void setGrantType(@NonNull String grantType) {
        this.grantType = grantType;
    }

    /**
     *
     * @return The application's Client identifier.
     */
    @NonNull
    public String getClientId() {
        return clientId;
    }

    /**
     *
     * @param clientId Application's Client identifier.
     */
    public void setClientId(@NonNull String clientId) {
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
    @NonNull
    public String getUsername() {
        return username;
    }

    /**
     *
     * @param username An username
     */
    public void setUsername(@NonNull String username) {
        this.username = username;
    }

    /**
     *
     * @return An password
     */
    @NonNull
    public String getPassword() {
        return password;
    }

    /**
     *
     * @param password An password
     */
    public void setPassword(@NonNull String password) {
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
    public void setScope(@NonNull String scope) {
        this.scope = scope;
    }

    /**
     *
     * @return this object as a Map
     */
    public Map<String, String> toMap() {
        Map<String, String> m = new SecureGrantMap();
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

