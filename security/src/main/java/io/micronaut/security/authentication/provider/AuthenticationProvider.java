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
package io.micronaut.security.authentication.provider;

import io.micronaut.context.annotation.Executable;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.Indexed;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.order.Ordered;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;

/**
 * Defines an API to authenticate a user with the given request.
 * @since 4.5.0
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
@Indexed(AuthenticationProvider.class)
public interface AuthenticationProvider<T, I, S> extends Ordered {

    /**
     * Authenticates a user with the given request.
     * If authenticated successfully return {@link AuthenticationResponse#success(String)}.
     * If not authenticated return {@link AuthenticationResponse#failure()}.
     * If your implementation is blocking, annotate the overriden method with {@link Blocking} and it will be safely executed on a
     * dedicated thread in order to not block the main reactive chain of execution.
     * @param requestContext The context request (typically an HTTP Request).
     * @param authRequest The credentials to authenticate
     * @return An {@link AuthenticationResponse} indicating either success or failure.
     */
    @NonNull
    @Executable
    AuthenticationResponse authenticate(@Nullable T requestContext, @NonNull AuthenticationRequest<I, S> authRequest);

    /**
     * Authenticates a user with the given request.
     * If authenticated successfully return {@link AuthenticationResponse#success(String)}.
     * If not authenticated return {@link AuthenticationResponse#failure()}.
     * If your implementation is blocking, annotate the overriden method with {@link Blocking} and it will be safely executed on a
     * dedicated thread in order to not block the main reactive chain of execution.
     * @param authRequest The credentials to authenticate
     * @return An {@link AuthenticationResponse} indicating either success or failure.
     */
    @NonNull
    @Executable
    default  AuthenticationResponse authenticate(@NonNull AuthenticationRequest<I, S>  authRequest) {
        return authenticate(null, authRequest);
    }
}
