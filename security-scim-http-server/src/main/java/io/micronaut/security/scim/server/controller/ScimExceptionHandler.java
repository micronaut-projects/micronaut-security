/*
 * Copyright 2017-2026 original authors
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
package io.micronaut.security.scim.server.controller;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.scim.server.exception.ScimException;
import io.micronaut.security.scim.server.protocol.ScimError;
import io.micronaut.security.scim.server.protocol.ScimMediaType;
import jakarta.inject.Singleton;

@Internal
@Produces({ScimMediaType.APPLICATION_SCIM_JSON, MediaType.APPLICATION_JSON})
@Requires(classes = ExceptionHandler.class)
@Singleton
final class ScimExceptionHandler implements ExceptionHandler<ScimException, MutableHttpResponse<ScimError>> {
    @Override
    public MutableHttpResponse<ScimError> handle(HttpRequest request, ScimException exception) {
        int code = exception.getStatus().getCode();
        return HttpResponse.status(exception.getStatus())
            .contentType(ScimMediaType.APPLICATION_SCIM_JSON_TYPE)
            .body(ScimError.of(code, exception.getScimType(), exception.getMessage()));
    }
}
