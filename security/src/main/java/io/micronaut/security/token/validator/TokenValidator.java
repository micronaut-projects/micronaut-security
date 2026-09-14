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
package io.micronaut.security.token.validator;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.order.Ordered;
import io.micronaut.security.authentication.Authentication;
import org.reactivestreams.Publisher;

/**
 * Responsible for token validation and claims retrieval.
 *
 * @author Sergio del Amo
 * @param <T> Request
 * @since 1.0
 */
public interface TokenValidator<T> extends Ordered {

    /**
     * Validates the provided token and returns the authentication state.
     *
     * <p> An implementation of this method should never block
     * (for example, waiting for a result of an IO operation) as it's called from the event loop.
     * Instead, it should immediately return a Publisher that is filled with an authentication result
     * when the result is available.
     *
     * <p> Validators are invoked sequentially, in {@link Ordered} order, with the first match winning:
     * a validator is only subscribed once every higher precedence validator has completed empty for the
     * same token, and once a validator emits an authentication no lower precedence validator is subscribed.
     *
     * @param token The token string
     * @param request The current request (or null)
     * @return An authentication publisher. If the publisher emits an error, the error is treated as a failed
     * validation by this validator: it is logged (without the token value) and the next validator in order will be
     * attempted, exactly as if the publisher had been empty. Errors are never propagated to the caller, so they
     * result in an unauthenticated request rather than a server error. If the publisher is empty, the next validator
     * in order will be attempted. If the publisher emits an authentication, that authentication will be used and no
     * further validators will be attempted.
     */
    @NonNull
    @SingleResult
    Publisher<Authentication> validateToken(@NonNull String token,
                                            @Nullable T request);
}
