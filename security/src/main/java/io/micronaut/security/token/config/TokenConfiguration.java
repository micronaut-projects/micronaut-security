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
package io.micronaut.security.token.config;

import edu.umd.cs.findbugs.annotations.NonNull;
import io.micronaut.core.util.Toggleable;

/**
 * Defines Security Token Configuration.
 * @author Sergio del Amo
 * @since 1.0
 */
public interface TokenConfiguration extends Toggleable {

    String DEFAULT_ROLES_NAME = "roles";

    String DEFAULT_NAME_KEY = "sub";

    /**
     * Key which will be used in the {@link io.micronaut.security.authentication.Authentication#getAttributes()} for the User`s roles.
     *
     * @return The key used for the user's roles within the user's attributes. e.g. "roles".
     */
    @NonNull
    String getRolesName();

    /**
     * Key which will be used in the {@link io.micronaut.security.authentication.Authentication#getAttributes()} for the User`s name.
     *
     * @return The key used for the user's name within the user's attributes. e.g. "sub".
     */
    @NonNull
    String getNameKey();
}
