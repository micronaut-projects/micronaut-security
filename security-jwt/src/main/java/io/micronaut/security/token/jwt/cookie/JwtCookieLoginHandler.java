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
package io.micronaut.security.token.jwt.cookie;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.UserDetails;
import io.micronaut.security.handlers.RedirectingLoginHandler;
import io.micronaut.security.token.jwt.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.jwt.generator.JwtGeneratorConfiguration;
import io.micronaut.security.token.jwt.render.AccessRefreshToken;

import javax.inject.Singleton;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(
        property = "micronaut.security.token.jwt.cookie.redirect.enabled",
        defaultValue = "true",
        value = "true"
)
@Singleton
public class JwtCookieLoginHandler implements RedirectingLoginHandler {

    protected final JwtCookieConfiguration jwtCookieConfiguration;
    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;
    protected final JwtGeneratorConfiguration jwtGeneratorConfiguration;
    protected final JwtCookieGenerator jwtCookieGenerator;

    /**
     * @param jwtCookieConfiguration      JWT Cookie Configuration
     * @param jwtGeneratorConfiguration   JWT Generator Configuration
     * @param accessRefreshTokenGenerator Access Refresh Token Generator
     * @param jwtCookieGenerator
     */
    public JwtCookieLoginHandler(JwtCookieConfiguration jwtCookieConfiguration,
                                 JwtGeneratorConfiguration jwtGeneratorConfiguration,
                                 AccessRefreshTokenGenerator accessRefreshTokenGenerator,
                                 JwtCookieGenerator jwtCookieGenerator) {
        this.jwtCookieConfiguration = jwtCookieConfiguration;
        this.jwtGeneratorConfiguration = jwtGeneratorConfiguration;
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
        this.jwtCookieGenerator = jwtCookieGenerator;
    }

    @Override
    public HttpResponse loginSuccess(UserDetails userDetails, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshTokenOptional = accessRefreshTokenGenerator.generate(userDetails);
        if (accessRefreshTokenOptional.isPresent()) {
            Cookie cookie = jwtCookieGenerator.generate(accessRefreshTokenOptional.get().getAccessToken(), request.isSecure());
            try {
                URI location = new URI(jwtCookieConfiguration.getLoginSuccessTargetUrl());
                return HttpResponse.seeOther(location).cookie(cookie);
            } catch (URISyntaxException e) {
                return HttpResponse.serverError();
            }

        }
        return HttpResponse.serverError();
    }

    @Override
    public HttpResponse loginFailed(AuthenticationFailed authenticationFailed) {
        try {
            URI location = new URI(jwtCookieConfiguration.getLoginFailureTargetUrl());
            return HttpResponse.seeOther(location);
        } catch (URISyntaxException e) {
            return HttpResponse.serverError();
        }
    }
}
