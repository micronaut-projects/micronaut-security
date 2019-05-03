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

package io.micronaut.security.oauth2.endpoint.authorization.response;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.server.exceptions.ExceptionHandler;

import javax.inject.Singleton;

/**
 * An exception handler for {@link AuthorizationErrorResponseException}.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Singleton
@Requires(classes = {AuthorizationErrorResponseException.class, ExceptionHandler.class})
public class AuthorizationErrorResponseExceptionHandler implements ExceptionHandler<AuthorizationErrorResponseException, HttpResponse> {

    @Override
    public HttpResponse handle(HttpRequest request, AuthorizationErrorResponseException exception) {
        return HttpResponse.badRequest(exception.getAuthorizationErrorResponse());
    }
}
