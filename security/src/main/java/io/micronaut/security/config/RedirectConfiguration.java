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
package io.micronaut.security.config;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * @author Sergio del Amo
 * @since 2.0.0
 */
public interface RedirectConfiguration {

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a successful login.
     */
    @NonNull
    String getLoginSuccess();

    /**
     * @return String to be parsed into a URI which represents where the user is redirected to after a failed login.
     */
    @NonNull
    String getLoginFailure();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after logout.
     */
    @NonNull
    String getLogout();

    /**
     * @return configuration about where the user is redirected to after trying to access a secured route.
     */
    @NonNull
    UnauthorizedRedirectConfiguration getUnauthorized();

    /**
     * @return configuration about where the user is redirected to after trying to access a secured route for which the does not have sufficient roles.
     */
    @NonNull
    ForbiddenRedirectConfiguration getForbidden();

    /**
     * @return configuration about where the user is redirected to after executing the refresh token endpoint.
     */
    @NonNull
    RefreshRedirectConfiguration getRefresh();


    /**
     * @return If the user attempted to access a URL while unauthenticated, and was subsequently redirected to
     * login, redirect back to that URL post login (true). Use the static login success URL (false).
     */
    boolean isPriorToLogin();
}
