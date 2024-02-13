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

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

/**
 * Adapts between {@link io.micronaut.security.authentication.provider.AuthenticationProvider} to {@link ReactiveAuthenticationProvider}.
 * @param <T> Request Context Type
 * @param <I> Authentication Request Identity Type
 * @param <S> Authentication Request Secret Type
 */
@Internal
final class AuthenticationProviderAdapter<T, I, S> implements ReactiveAuthenticationProvider<T, I, S> {

    @NonNull
    private final AuthenticationProvider<T, I, S> authenticationProvider;

    @Nullable
    private final Scheduler scheduler;

    public AuthenticationProviderAdapter(@NonNull AuthenticationProvider<T, I, S> authenticationProvider,
                                         @NonNull Scheduler scheduler) {
        this.authenticationProvider = authenticationProvider;
        this.scheduler = scheduler;
    }

    public AuthenticationProviderAdapter(@NonNull AuthenticationProvider<T, I, S> authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
        this.scheduler = null;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<I, S> authenticationRequest) {
        Mono<AuthenticationResponse> authenticationResponseMono = Mono.fromCallable(() -> authenticationProvider.authenticate(requestContext, authenticationRequest));
        return scheduler != null ? authenticationResponseMono.subscribeOn(scheduler) : authenticationResponseMono;
    }
}
