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
package io.micronaut.security.handlers;

import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;

/**
 * Defines how to respond to a successful or failed login attempt.
 * @author Sergio del Amo
 * @since 1.0
 */
public interface LoginHandler {

    /**
     * @param authentication Authenticated user's representation.
     * @param request The {@link HttpRequest} being executed
     * @return An HTTP Response. Eg. a redirect or an JWT token rendered to the response
     */
    MutableHttpResponse<?> loginSuccess(Authentication authentication, HttpRequest<?> request);

    /**
     * @param authentication Authenticated user's representation.
     * @param refreshToken The refresh token
     * @param request The {@link HttpRequest} being executed
     * @return An HTTP Response. Eg. a redirect or an JWT token rendered to the response
     */
    MutableHttpResponse<?> loginRefresh(Authentication authentication, String refreshToken, HttpRequest<?> request);

    /**
     * @param authenticationResponse Object encapsulates the Login failure
     * @param request The {@link HttpRequest} being executed
     * @return An HTTP Response. Eg. a redirect or 401 response
     */
    MutableHttpResponse<?> loginFailed(AuthenticationResponse authenticationResponse, HttpRequest<?> request);
}
