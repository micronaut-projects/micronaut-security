/*
 * Copyright 2017-2018 original authors
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

/**
 * Password Grant.
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.3.2">Access Token Request</a>
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
public class PasswordGrant {

    @Nonnull
    @JsonProperty("grant_type")
    private String grantType = GrantType.PASSWORD.getGrantType();

    @Nullable
    private String scope;

    @Nonnull
    private String username;

    @Nonnull
    private String password;

    /**
     * Instantiates a PasswordGrant.
     */
    public PasswordGrant() {

    }

    /**
     *
     * @return password
     */
    @Nonnull
    public String getGrantType() {
        return grantType;
    }

    /**
     *
     * @return The resource owner username.
     */
    @Nonnull
    public String getUsername() {
        return username;
    }

    /**
     *
     * @param username The resource owner username.
     */
    public void setUsername(@Nonnull String username) {
        this.username = username;
    }

    /**
     *
     * @return The resource owner password.
     */
    @Nonnull
    public String getPassword() {
        return password;
    }

    /**
     *
     * @param password The resource owner password.
     */
    public void setPassword(@Nonnull String password) {
        this.password = password;
    }

    /**
     *
     * @return Optional requested scope values for the access token.
     */
    @Nonnull
    public String getScope() {
        return scope;
    }

    /**
     *
     * @param scope Optional requested scope values for the access token.
     */
    public void setScope(@Nonnull String scope) {
        this.scope = scope;
    }
}
