/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.config;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;

/**
 * Get redirection URLs combining context path and redirect configuration.
 * @author Sergio del Amo
 * @since 3.7.2
 */
@DefaultImplementation(DefaultRedirectService.class)
public interface RedirectService {
    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a successful login.
     */
    @NonNull
    String loginSuccessUrl();

    /**
     * @return String to be parsed into a URI which represents where the user is redirected to after a failed login.
     */
    @NonNull
    String loginFailureUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after logout.
     */
    @NonNull
    String logoutUrl();

    /**
     * @return where the user is redirected to after trying to access a secured route.
     */
    @NonNull
    String unauthorizedUrl();

    /**
     * @return where the user is redirected to after trying to access a secured route for which the does not have sufficient roles.
     */
    @NonNull
    String forbiddenUrl();

    /**
     * @return where the user is redirected to after executing the refresh token endpoint.
     */
    @NonNull
    String refreshUrl();
}
