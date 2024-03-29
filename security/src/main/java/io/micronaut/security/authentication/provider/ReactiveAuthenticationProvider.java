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
import io.micronaut.core.annotation.Indexed;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.async.annotation.SingleResult;
import io.micronaut.core.order.Ordered;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;

/**
 * Defines a reactive authentication provider.
 *
 * @since 4.5.0
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
@Indexed(ReactiveAuthenticationProvider.class)
public interface ReactiveAuthenticationProvider<T, I, S> extends Ordered {

    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link Authentication}.
     *
     * Publishers <b>MUST emit cold observables</b>! This method will be called for
     * all authenticators for each authentication request and it is assumed no work
     * will be done until the publisher is subscribed to.
     *
     * @param requestContext rquest context (it may be an HTTP request).
     * @param authenticationRequest The credentials to authenticate
     * @return A publisher that emits 0 or 1 responses
     */
    @NonNull
    @SingleResult
    Publisher<AuthenticationResponse> authenticate(@Nullable T requestContext,
                                                   @NonNull AuthenticationRequest<I, S> authenticationRequest);

    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link Authentication}.
     *
     * Publishers <b>MUST emit cold observables</b>! This method will be called for
     * all authenticators for each authentication request and it is assumed no work
     * will be done until the publisher is subscribed to.
     *
     * @param authenticationRequest The credentials to authenticate
     * @return A publisher that emits 0 or 1 responses
     */
    @NonNull
    @SingleResult
    default Publisher<AuthenticationResponse> authenticate(@NonNull AuthenticationRequest<I, S> authenticationRequest) {
        return authenticate(null, authenticationRequest);
    }
}
