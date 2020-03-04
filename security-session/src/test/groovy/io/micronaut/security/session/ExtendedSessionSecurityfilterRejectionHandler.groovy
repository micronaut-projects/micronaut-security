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
package io.micronaut.security.session

import io.micronaut.context.annotation.Replaces
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.MutableHttpResponse
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthorizationException

import javax.inject.Singleton

@Requires(property = 'spec.name', value = "RejectionHandlerResolutionSpec")
@Singleton
@Replaces(RedirectingAuthorizationExceptionHandler)
class ExtendedSessionSecurityfilterRejectionHandler implements ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> {

    @Override
    MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        return null
    }
}
