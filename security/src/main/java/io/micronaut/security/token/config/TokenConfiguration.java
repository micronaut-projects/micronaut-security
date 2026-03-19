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
package io.micronaut.security.token.config;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.authentication.Authentication;

/**
 * Defines Security Token Configuration.
 * @author Sergio del Amo
 * @since 1.0
 */
public interface TokenConfiguration extends Toggleable {

    String DEFAULT_ROLES_NAME = "roles";

    String DEFAULT_NAME_KEY = "sub";

    String DEFAULT_ROLES_SEPARATOR = null;

    boolean DEFAULT_STORE_AS_ATTRIBUTE = false;

    String DEFAULT_TOKEN_ATTRIBUTE_NAME = "token";

    /**
     *
     * @return Whether to store the token as an attribute in  {@link io.micronaut.security.authentication.Authentication#getAttributes()}. Default value: `false`.
     */
    default boolean isStoreAsAttribute() {
        return DEFAULT_STORE_AS_ATTRIBUTE;
    }

    /**
     *
     * @return the {@link Authentication#getAttributes()} key to store the token if {@link TokenConfiguration#isStoreAsAttribute()} returns {@literal true}. Default value {@value #DEFAULT_TOKEN_ATTRIBUTE_NAME}.
     */
    @NonNull
    default String getAttributeName() {
        return DEFAULT_TOKEN_ATTRIBUTE_NAME;
    }

    /**
     * Key which will be used in the {@link io.micronaut.security.authentication.Authentication#getAttributes()} for the User`s roles.
     *
     * @return The key used for the user's roles within the user's attributes. e.g. "roles".
     */
    @NonNull
    default String getRolesName() {
        return DEFAULT_ROLES_NAME;
    }

    /**
     * Key which will be used in the {@link io.micronaut.security.authentication.Authentication#getAttributes()} for the User`s name.
     *
     * @return The key used for the user's name within the user's attributes. e.g. "sub".
     */
    @NonNull
    default String getNameKey() {
        return DEFAULT_NAME_KEY;
    }

    /**
     * Separator which will be used for splitting the roles before processing the {@link io.micronaut.security.authentication.Authentication}.
     *
     * @return The separator used for splitting the users roles
     */
    @Nullable
    default String getRolesSeparator() {
        return DEFAULT_ROLES_SEPARATOR;
    }
}
