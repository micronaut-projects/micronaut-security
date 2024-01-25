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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import org.reactivestreams.Publisher;

/**
 * Defines an authentication provider.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 * @param <T> Request Context Type
 * @deprecated Use {@link io.micronaut.security.authentication.provider.AuthenticationProvider} for an imperative API or {@link ReactiveAuthenticationProvider} for a reactive API instead.
 */
@Deprecated(forRemoval = true, since = "4.5.0")
public interface AuthenticationProvider<T> {
    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link Authentication}.
     *
     * Publishers <b>MUST emit cold observables</b>! This method will be called for
     * all authenticators for each authentication request and it is assumed no work
     * will be done until the publisher is subscribed to.
     *
     * @param httpRequest The http request
     * @param authenticationRequest The credentials to authenticate
     * @return A publisher that emits 0 or 1 responses
     */
    @NonNull
    Publisher<AuthenticationResponse> authenticate(@Nullable T httpRequest, AuthenticationRequest<?, ?> authenticationRequest);
}
