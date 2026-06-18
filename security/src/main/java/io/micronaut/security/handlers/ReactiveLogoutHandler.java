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
package io.micronaut.security.handlers;

import io.micronaut.core.async.annotation.SingleResult;
import org.jspecify.annotations.NonNull;
import org.reactivestreams.Publisher;

/**
 * Responsible for logging the user out reactively and returning
 * an appropriate response.
 *
 * <p>Publishers <b>MUST be cold</b>. It is assumed no work
 * will be done until the publisher is subscribed to.</p>
 *
 * @author Sergio del Amo
 * @since 5.1.0
 * @param <I> Request
 * @param <O> Response
 */
@FunctionalInterface
public interface ReactiveLogoutHandler<I, O> {

    /**
     * @param request The HTTP Request being executed
     * @return A publisher that emits 0 or 1 responses built after the user logs out
     */
    @NonNull
    @SingleResult
    Publisher<O> logout(@NonNull I request);
}
