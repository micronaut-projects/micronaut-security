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

package io.micronaut.security.oauth2.endpoints;

import io.micronaut.core.util.Toggleable;

import javax.annotation.Nonnull;

/**
 * Configuration for {@link AuthorizationCodeController}.
 *
 * @author Sergio del Amo
 * @since 1.0.0
 */
public interface AuthorizationCodeControllerConfiguration extends Toggleable {

    /**
     * The base path the authorization controller responds to.
     *
     * @return The controller path
     */
    @Nonnull
    String getControllerPath();

    /**
     * The path to respond to callbacks. Appended to the controller path.
     *
     * @return The controller's callback path
     */
    @Nonnull
    String getCallbackPath();

    /**
     * The path to listen for login requests. Appended to the controller path.
     *
     * @return The controller's login path
     */
    @Nonnull
    String getLoginPath();
}
