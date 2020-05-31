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

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.config.RedirectConfiguration;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.errors.PriorToLoginPersistence;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.AccessTokenConfiguration;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.time.Duration;
import java.util.Optional;

/**
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "cookie")
@Singleton
public class JwtCookieLoginHandler extends CookieLoginHandler {

    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final AccessTokenConfiguration accessTokenConfiguration;

    /**
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @deprecated Use {@link JwtCookieLoginHandler(RedirectConfiguration, JwtCookieConfiguration, AccessTokenConfiguration, AccessRefreshTokenGenerator,PriorToLoginPersistence)} instead.
     */
    @Deprecated
    public JwtCookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        super(jwtCookieConfiguration, jwtCookieConfiguration.getLoginSuccessTargetUrl(), jwtCookieConfiguration.getCookieName());
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    /**
     * @param redirectConfiguration Redirect configuration
     * @param jwtCookieConfiguration JWT Cookie Configuration
     * @param accessTokenConfiguration JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param priorToLoginPersistence Prior To Login Persistence Mechanism
     */
    @Inject
    public JwtCookieLoginHandler(RedirectConfiguration redirectConfiguration,
                                 JwtCookieConfiguration jwtCookieConfiguration,
                                 AccessTokenConfiguration accessTokenConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                 PriorToLoginPersistence priorToLoginPersistence) {
        super(jwtCookieConfiguration, redirectConfiguration, priorToLoginPersistence);
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    @Override
    protected Optional<String> cookieValue(UserDetails userDetails, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshTokenOptional = accessRefreshTokenGenerator.generate(userDetails);
        return accessRefreshTokenOptional.map(AccessRefreshToken::getAccessToken);
    }

    @Override
    protected Duration cookieExpiration(UserDetails userDetails, HttpRequest<?> request) {
        return Duration.ofSeconds(accessTokenConfiguration.getExpiration());
    }
}
