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

import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;

/**
 * Adapter pattern from {@link BlockingAuthenticationProvider} to {@link AuthenticationProvider}.
 * @since 4.5.0
 */
public class BlockingAuthenticationProviderAdapter<T> implements AuthenticationProvider<T> {
    private final BlockingAuthenticationProvider<T> blockingAuthenticationProvider;
    private final Scheduler scheduler;

    public BlockingAuthenticationProviderAdapter(BlockingAuthenticationProvider<T> blockingAuthenticationProvider,
                                                 Scheduler scheduler) {
        this.blockingAuthenticationProvider = blockingAuthenticationProvider;
        this.scheduler = scheduler;
    }
    @Override
    public Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        return Mono.fromCallable(() -> blockingAuthenticationProvider.authenticate(httpRequest, authenticationRequest))
                .subscribeOn(scheduler);
    }
}
