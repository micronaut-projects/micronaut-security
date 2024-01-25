/*
 * Copyright 2017-2024 original authors
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

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.authentication.AuthenticationProvider;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;

/**
 * Adapts from {@link AuthenticationProvider} to {@link ReactiveAuthenticationProvider}.
 * @author Sergio del Amo
 * @since 4.5.1
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
@Internal
@Deprecated(forRemoval = true, since = "4.5.1")
public final class ReactiveAuthenticationProviderAdapter<T, I, S> implements ReactiveAuthenticationProvider<T, I, S> {

    private final AuthenticationProvider<T> authenticationProvider;

    public ReactiveAuthenticationProviderAdapter(AuthenticationProvider<T> authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        return authenticationProvider.authenticate(requestContext, authenticationRequest);
    }
}
