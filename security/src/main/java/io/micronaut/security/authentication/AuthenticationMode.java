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

import io.micronaut.core.annotation.Internal;

/**
 * Different authentication strategies shipped with Micronaut Security.
 *
 * Depending on the authentication used different {@link io.micronaut.security.handlers.LoginHandler} and
 * {@link io.micronaut.security.handlers.LogoutHandler} are enabled.
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Internal
public enum AuthenticationMode {
    BEARER,
    COOKIE,
    IDTOKEN,
    SESSION;

    /**
     * Constructor.
     */
    AuthenticationMode() {
    }

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}
