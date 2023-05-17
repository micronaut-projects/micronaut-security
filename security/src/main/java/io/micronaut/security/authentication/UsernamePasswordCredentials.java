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
package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Nullable;
import io.micronaut.serde.annotation.Serdeable;
import jakarta.validation.constraints.NotBlank;

import java.io.Serializable;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Serdeable
public class UsernamePasswordCredentials implements Serializable, AuthenticationRequest<String, String> {
    @NotBlank
    @Nullable
    private String username;

    @NotBlank
    @Nullable
    private String password;

    /**
     *
     * @param username e.g. admin
     * @param password raw password
     */
    public UsernamePasswordCredentials(@Nullable String username, @Nullable String password) {
        this.username = username;
        this.password = password;
    }

    /**
     * username getter.
     * @return e.g. admin
     */
    @Nullable
    public String getUsername() {
        return username;
    }

    /**
     * username setter.
     * @param username e.g. admin
     */
    public void setUsername(@Nullable String username) {
        this.username = username;
    }

    /**
     * password getter.
     * @return raw password
     */
    @Nullable
    public String getPassword() {
        return password;
    }

    /**
     * password setter.
     * @param password raw password
     */
    public void setPassword(@Nullable String password) {
        this.password = password;
    }

    @Override
    @Nullable
    public String getIdentity() {
        return getUsername();
    }

    /**
     * Returns password conforming to {@link AuthenticationRequest} blueprint.
     * @return secret string.
     */
    @Override
    @Nullable
    public String getSecret() {
        return getPassword();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        UsernamePasswordCredentials that = (UsernamePasswordCredentials) o;

        if (username != null ? !username.equals(that.username) : that.username != null) {
            return false;
        }
        return password != null ? password.equals(that.password) : that.password == null;
    }

    @Override
    public int hashCode() {
        int result = username != null ? username.hashCode() : 0;
        result = 31 * result + (password != null ? password.hashCode() : 0);
        return result;
    }
}
