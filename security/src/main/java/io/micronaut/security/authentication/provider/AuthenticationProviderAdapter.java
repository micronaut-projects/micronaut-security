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

import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

/**
 * Adapts between {@link AuthenticationProvider} to {@link ReactiveAuthenticationProvider}.
 * @param <T> Request
 */
@Internal
public final class AuthenticationProviderAdapter<T> implements ReactiveAuthenticationProvider<T> {

    @NonNull
    private final AuthenticationProvider<T> authenticationProvider;

    private final Scheduler scheduler;

    public AuthenticationProviderAdapter(BeanContext beanContext,
                                         Scheduler scheduler,
                                         @NonNull AuthenticationProvider<T> authenticationProvider) {
        this(authenticationProvider,
                AuthenticationProviderUtils.isAuthenticateBlocking(beanContext, authenticationProvider) ? scheduler : null);
    }

    public AuthenticationProviderAdapter(@NonNull AuthenticationProvider<T> authenticationProvider,
                                          @Nullable Scheduler scheduler) {
        this.authenticationProvider = authenticationProvider;
        this.scheduler = scheduler;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<?, ?> authenticationRequest) {
        Mono<AuthenticationResponse> authenticationResponseMono = Mono.fromCallable(() -> authenticationProvider.authenticate(requestContext, authenticationRequest));
        return scheduler != null ? authenticationResponseMono.subscribeOn(scheduler) : authenticationResponseMono;
    }
}
