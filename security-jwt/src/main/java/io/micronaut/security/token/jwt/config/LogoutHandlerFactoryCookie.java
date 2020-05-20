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

package io.micronaut.security.token.jwt.config;

import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.security.token.jwt.cookie.JwtCookieClearerLogoutHandler;
import io.micronaut.security.token.jwt.cookie.JwtCookieConfiguration;
import javax.inject.Singleton;

/**
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(condition = LogoutHandlerFactoryCookieCondition.class)
@Factory
public class LogoutHandlerFactoryCookie {

    protected final RedirectConfiguration redirectConfiguration;
    protected final JwtCookieConfiguration jwtCookieConfiguration;

    /**
     *
     * @param redirectConfiguration Redirect Configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     */
    public LogoutHandlerFactoryCookie(RedirectConfiguration redirectConfiguration,
                                      JwtCookieConfiguration jwtCookieConfiguration) {
        this.redirectConfiguration = redirectConfiguration;
        this.jwtCookieConfiguration = jwtCookieConfiguration;
    }

    /**
     *
     * @return a {@link LogoutHandler} singleton of type {@link JwtCookieClearerLogoutHandler}.
     */
    @Singleton
    public LogoutHandler createLogoutHandler() {
        return new JwtCookieClearerLogoutHandler(jwtCookieConfiguration, redirectConfiguration);
    }

}
