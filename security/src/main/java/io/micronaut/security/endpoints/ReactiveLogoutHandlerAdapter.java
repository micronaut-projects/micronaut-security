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
package io.micronaut.security.endpoints;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.security.handlers.LogoutHandler;
import io.micronaut.security.handlers.ReactiveLogoutHandler;
import org.jspecify.annotations.NonNull;
import org.reactivestreams.Publisher;

/**
 * Adapter from {@link LogoutHandler} to {@link ReactiveLogoutHandlerAdapter}.
 *
 * @param <I> Request
 * @param <O> Response
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Internal
class ReactiveLogoutHandlerAdapter<I, O> implements ReactiveLogoutHandler<I, O> {
    private LogoutHandler<I, O> logoutHandler;

    ReactiveLogoutHandlerAdapter(LogoutHandler<I, O> logoutHandler) {
        this.logoutHandler = logoutHandler;
    }

    @Override
    public @NonNull Publisher<O> logout(@NonNull I request) {
        return Publishers.just(logoutHandler.logout(request));
    }
}
