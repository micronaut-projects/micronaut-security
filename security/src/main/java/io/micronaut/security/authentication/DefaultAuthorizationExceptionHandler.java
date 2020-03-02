/*
 * Copyright 2017-2020 original authors
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
package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Internal;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.server.exceptions.ExceptionHandler;
import io.micronaut.security.handlers.RejectionHandler;
import io.reactivex.Flowable;

import javax.inject.Singleton;

/**
 * Provides the default behavior for responding to an {@link AuthorizationException}.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
@Singleton
public class DefaultAuthorizationExceptionHandler implements ExceptionHandler<AuthorizationException, MutableHttpResponse<?>> {

    private final RejectionHandler rejectionHandler;

    /**
     * @param rejectionHandler The rejection handler
     */
    @Internal
    DefaultAuthorizationExceptionHandler(RejectionHandler rejectionHandler) {
        this.rejectionHandler = rejectionHandler;
    }

    @Override
    public MutableHttpResponse<?> handle(HttpRequest request, AuthorizationException exception) {
        return Flowable.fromPublisher(rejectionHandler.reject(request, exception.isForbidden())).blockingFirst();
    }
}
