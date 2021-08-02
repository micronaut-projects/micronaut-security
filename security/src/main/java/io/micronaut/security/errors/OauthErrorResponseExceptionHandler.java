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
package io.micronaut.security.errors;

import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.server.exceptions.ExceptionHandler;

import jakarta.inject.Singleton;
import java.util.HashMap;
import java.util.Map;

/**
 * Returns an application/json response for a {@link OauthErrorResponseException} with status 400.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-5.2">OAuth 2.0 Error Response</a>
 *
 * @author sdelamo
 * @since 2.0.0
 */
@Requires(classes = OauthErrorResponseException.class)
@Produces
@Singleton
public class OauthErrorResponseExceptionHandler implements ExceptionHandler<OauthErrorResponseException, MutableHttpResponse<?>> {

        @Override
        public MutableHttpResponse<?> handle(HttpRequest request, OauthErrorResponseException exception) {
                return HttpResponse.badRequest(responseBody(exception));
        }

        /**
         *
         * @param errorResponse Error Response
         * @return A Map which will be serialized as the body of the HTTP response
         */
        protected Map<String, Object> responseBody(ErrorResponse errorResponse) {
                Map<String, Object> m = new HashMap<>();
                m.put(ErrorResponse.JSON_KEY_ERROR, errorResponse.getError().toString());
                if (errorResponse.getErrorDescription() != null) {
                        m.put(ErrorResponse.JSON_KEY_ERROR_DESCRIPTION, errorResponse.getErrorDescription());
                }
                if (errorResponse.getErrorUri() != null) {
                        m.put(ErrorResponse.JSON_KEY_ERROR_URI, errorResponse.getErrorUri());
                }
                return m;
        }
}
