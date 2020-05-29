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
package io.micronaut.security.authentication;

import io.micronaut.context.annotation.Primary;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.hateoas.JsonError;
import io.micronaut.http.hateoas.Link;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.endpoints.LoginControllerConfiguration;
import io.micronaut.security.event.LoginFailedEvent;
import io.micronaut.security.handlers.LoginHandler;
import jdk.internal.jline.internal.Nullable;

import javax.inject.Singleton;


/**
 * Handles the server response when an {@link AuthenticationException} is thrown.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
@Primary
@Produces
public class AuthenticationExceptionHandler implements ExceptionHandler<AuthenticationException, MutableHttpResponse<?>> {
    protected final ApplicationEventPublisher eventPublisher;

    protected final LoginHandler loginHandler;
    protected final LoginControllerConfiguration loginControllerConfiguration;

    public AuthenticationExceptionHandler(ApplicationEventPublisher eventPublisher,
                                          @Nullable LoginHandler loginHandler,
                                          @Nullable LoginControllerConfiguration loginControllerConfiguration) {
        this.eventPublisher = eventPublisher;
        this.loginHandler = loginHandler;
        this.loginControllerConfiguration = loginControllerConfiguration;
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthenticationException exception) {
        AuthenticationResponse resp = exception.getResponse();
        if (resp != null) {
            eventPublisher.publishEvent(new LoginFailedEvent(resp));
            if (shouldBeHandledByLoginHandler(request)) {
                return loginHandler.loginFailed(resp, request);
            }
        }
        return handleByDefault(request, exception);
    }

    /**
     *
     * @param request The request for which the {@link AuthenticationException} was raised.
     * @return true if the response should be crafted by {@link LoginHandler#loginFailed(AuthenticationResponse)}
     */
    protected boolean shouldBeHandledByLoginHandler(HttpRequest request) {
        return loginHandler != null &&
                loginControllerConfiguration != null &&
                loginControllerConfiguration.getPath() != null &&
                request.getPath().equals(loginControllerConfiguration.getPath());
    }

    /**
     * Handles an exception and returns the result.
     *
     * @param request The request for which the {@link AuthenticationException} was raised.
     * @param exception The authentication exception
     * @return a 401 response with a {@link JsonError} in the body.
     */
    protected MutableHttpResponse<?> handleByDefault(HttpRequest request, AuthenticationException exception) {
        JsonError error = new JsonError(exception.getMessage());
        error.link(Link.SELF, Link.of(request.getUri()));
        return HttpResponse.unauthorized().body(error);
    }
}

