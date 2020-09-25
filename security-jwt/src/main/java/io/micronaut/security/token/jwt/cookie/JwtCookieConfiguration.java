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
package io.micronaut.security.token.jwt.cookie;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Deprecated
public interface JwtCookieConfiguration extends AccessTokenCookieConfiguration {

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a successful login.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLoginSuccess()} instead.
     */
    @Deprecated
    String getLoginSuccessTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after logout.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLogout()} instead.
     */
    @Deprecated
    String getLogoutTargetUrl();

    /**
     *
     * @return String to be parsed into a URI which represents where the user is redirected to after a failed login.
     * @deprecated Use {@link io.micronaut.security.config.RedirectConfiguration#getLoginFailure()} instead.
     */
    @Deprecated
    String getLoginFailureTargetUrl();

}
