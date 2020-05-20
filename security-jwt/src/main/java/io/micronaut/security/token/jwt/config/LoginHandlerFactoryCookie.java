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
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.jwt.cookie.JwtCookieConfiguration;
import io.micronaut.security.token.jwt.cookie.JwtCookieLoginHandler;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration;

import javax.inject.Singleton;

/**
 * @author Sergio del Amo
 * @since 2.0.0
 */
@Requires(beans = {AccessRefreshTokenGenerator.class, RedirectConfiguration.class, JwtCookieConfiguration.class, AccessTokenConfiguration.class})
@Requires(condition = LoginHandlerFactoryCookieCondition.class)
@Factory
public class LoginHandlerFactoryCookie {

    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final RedirectConfiguration redirectConfiguration;
    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final AccessTokenConfiguration accessTokenConfiguration;

    /**
     *
     * @param redirectConfiguration Redirect Configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration Access Token Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     */
    public LoginHandlerFactoryCookie(RedirectConfiguration redirectConfiguration,
                                     JwtCookieConfiguration jwtCookieConfiguration,
                                     AccessTokenConfiguration accessTokenConfiguration,
                                     AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.redirectConfiguration = redirectConfiguration;
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.accessTokenConfiguration = accessTokenConfiguration;
    }

    /**
     *
     * @return a {@link LoginHandler} singleton of type {@link JwtCookieLoginHandler}.
     */
    @Singleton
    public LoginHandler createLoginHandler() {
        return new JwtCookieLoginHandler(redirectConfiguration, jwtCookieConfiguration, accessTokenConfiguration, accessRefreshTokenGenerator);
    }

}
