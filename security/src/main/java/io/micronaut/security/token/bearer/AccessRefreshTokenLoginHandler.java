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
package io.micronaut.security.token.bearer;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.handlers.LoginHandler;
import io.micronaut.security.token.generator.AccessRefreshTokenGenerator;
import io.micronaut.security.token.render.AccessRefreshToken;
import jakarta.inject.Singleton;

import java.util.Optional;

/**
 * Implementation of {@link LoginHandler} for Token Based Authentication.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Requires(classes = {HttpRequest.class, MutableHttpResponse.class})
@Requires(property = SecurityConfigurationProperties.PREFIX + ".authentication", value = "bearer")
@Singleton
public class AccessRefreshTokenLoginHandler implements LoginHandler<HttpRequest<?>, MutableHttpResponse<?>> {
    protected final AccessRefreshTokenGenerator accessRefreshTokenGenerator;

    /**
     * @param accessRefreshTokenGenerator AccessRefresh Token generator
     */
    public AccessRefreshTokenLoginHandler(AccessRefreshTokenGenerator accessRefreshTokenGenerator) {
        this.accessRefreshTokenGenerator = accessRefreshTokenGenerator;
    }

    @Override
    public MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshTokenOptional = accessRefreshTokenGenerator.generate(authentication);
        if (accessRefreshTokenOptional.isPresent()) {
            return HttpResponse.ok(accessRefreshTokenOptional.get());
        }
        return HttpResponse.serverError();
    }

    @Override
    public MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request) {
        Optional<AccessRefreshToken> accessRefreshToken = accessRefreshTokenGenerator.generate(refreshToken, authentication);
        if (accessRefreshToken.isPresent()) {
            return HttpResponse.ok(accessRefreshToken.get());
        }
        return HttpResponse.serverError();
    }

    @Override
    public MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationFailed, HttpRequest<?> request) {
        throw new AuthenticationException(authenticationFailed.getMessage().orElse(null));
    }

}
