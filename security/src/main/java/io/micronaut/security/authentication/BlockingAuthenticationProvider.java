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
package io.micronaut.security.authentication;

import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.naming.Named;

/**
 * Defines an authentication provider.
 * @since 4.5.0
 * @param <T> Request
 */
public interface BlockingAuthenticationProvider<T> extends Named {

    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link Authentication}.
     *
     * Implementations of this blocking variation of {@link AuthenticationProvider} will be safely executed on a
     * dedicated thread in order to not block the main reactive chain of execution.
     *
     * @param httpRequest The http request
     * @param authenticationRequest The credentials to authenticate
     * @return An {@link AuthenticationResponse} indicating either success or failure.
     */
    @NonNull
    @Blocking
    AuthenticationResponse authenticate(@Nullable T httpRequest, AuthenticationRequest<?, ?> authenticationRequest);
}
