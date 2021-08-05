/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.testutils.authprovider;

import io.micronaut.core.annotation.Introspected;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Successful authentication scenario.
 */
@Introspected
public class SuccessAuthenticationScenario {
    @NonNull
    private String username;

    @Nullable
    private String password;

    @NonNull
    private List<String> roles;

    @NonNull
    Map<String, Object> attributes;

    /**
     *
     * @param username Username
     */
    public SuccessAuthenticationScenario(@NonNull String username) {
        this.username = username;
        this.roles = Collections.emptyList();
        this.attributes = Collections.emptyMap();
    }

    /**
     *
     * @param username Username
     * @param password Password
     */
    public SuccessAuthenticationScenario(@NonNull String username,
                                         @Nullable String password) {
        this.username = username;
        this.password = password;
        this.roles = Collections.emptyList();
        this.attributes = Collections.emptyMap();
    }

    /**
     *
     * @param username Username
     * @param roles Roles
     */
    public SuccessAuthenticationScenario(@NonNull String username,
                                         @NonNull List<String> roles) {
        this.username = username;
        this.roles = roles;
        this.attributes = Collections.emptyMap();
    }

    /**
     *
     * @param username Username
     * @param roles roles
     * @param attributes attributes
     */
    public SuccessAuthenticationScenario(@NonNull String username,
                                         @NonNull List<String> roles,
                                         @NonNull Map<String, Object> attributes) {
        this.username = username;
        this.roles = roles;
        this.attributes = attributes;
    }

    /**
     *
     * @return Username
     */
    @NonNull
    public String getUsername() {
        return username;
    }

    /**
     *
     * @return password
     */
    @Nullable
    public String getPassword() {
        return password;
    }

    /**
     *
     * @return Roles
     */
    @NonNull
    public List<String> getRoles() {
        return roles;
    }

    /**
     *
     * @return Attributes
     */
    @NonNull
    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
