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
 * Password Grant Request.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public class PasswordGrant {
    public static final String KEY_GRANT_TYPE = "grant_type";
    public static final String KEY_CLIENT_ID = "client_id";
    public static final String KEY_CLIENT_SECRET = "client_secret";
    public static final String KEY_USERNAME = "username";
    public static final String KEY_PASSWORD = "password";
    public static final String KEY_SCOPE = "scope";

    @Nonnull
    @JsonProperty(KEY_GRANT_TYPE)
    private String grantType = GrantType.PASSWORD.getGrantType();

    @Nonnull
    @JsonProperty(KEY_CLIENT_ID)
    private String clientId;

    @Nullable
    @JsonProperty(KEY_CLIENT_SECRET)
    private String clientSecret;

    @Nonnull
    private String username;

    @Nonnull
    private String password;

    @Nullable
    private String scope;

    /**
     * Instantiate Password Grant.
     */
    public PasswordGrant() {
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
     * @return this object as a Map
     */
    public Map<String, String> toMap() {
        Map<String, String> m = new HashMap<>();
        m.put(KEY_GRANT_TYPE, getGrantType());
        m.put(KEY_CLIENT_ID, getClientId());
        if (getClientSecret() != null) {
            m.put(KEY_CLIENT_SECRET, getClientSecret());
        }
        m.put(KEY_USERNAME, getUsername());
        m.put(KEY_PASSWORD, getPassword());

        if (getScope() != null) {
            m.put(KEY_SCOPE, getScope());
        }
        return m;
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
}

