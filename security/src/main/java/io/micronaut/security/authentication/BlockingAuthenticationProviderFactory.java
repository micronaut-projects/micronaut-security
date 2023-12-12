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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.core.annotation.Internal;
import io.micronaut.scheduling.TaskExecutors;
import jakarta.inject.Named;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;

/**
 * A factory for adapting {@link BlockingAuthenticationProvider} beans to expose them as {@link AuthenticationProvider}.
 *
 * @since 4.5.0
 */
@Factory
@Internal
class BlockingAuthenticationProviderFactory {

    private final Scheduler scheduler;

    BlockingAuthenticationProviderFactory(@Named(TaskExecutors.BLOCKING) ExecutorService executorService) {
        this.scheduler = Schedulers.fromExecutorService(executorService);
    }

    /**
     * Creates an adapted {@link AuthenticationProvider} for each provided instance of {@link BlockingAuthenticationProvider}.
     *
     * <p>
     * NOTE - If there are multiple instances of {@link BlockingAuthenticationProvider} in the application context, then they
     * must be annotated with a {@link jakarta.inject.Qualifier} such as {@link Named}.
     * </p>
     *
     * @param blockingAuthenticationProvider An instance of {@link BlockingAuthenticationProvider} to be adapted
     * @return An {@link AuthenticationProvider} adapted from the blocking provider
     * @param <T> The request type
     */
    @EachBean(BlockingAuthenticationProvider.class)
    <T> AuthenticationProvider<T> createAuthenticationProvider(BlockingAuthenticationProvider<T> blockingAuthenticationProvider) {
        return new BlockingAuthenticationProviderAdapter<>(blockingAuthenticationProvider, scheduler);
    }

    private static class BlockingAuthenticationProviderAdapter<T> implements AuthenticationProvider<T> {

        private final BlockingAuthenticationProvider<T> blockingAuthenticationProvider;

        private final Scheduler scheduler;

        private BlockingAuthenticationProviderAdapter(BlockingAuthenticationProvider<T> blockingAuthenticationProvider, Scheduler scheduler) {
            this.blockingAuthenticationProvider = blockingAuthenticationProvider;
            this.scheduler = scheduler;
        }

        @Override
        public Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            return Mono.fromCallable(() -> blockingAuthenticationProvider.authenticate(httpRequest, authenticationRequest))
                    .subscribeOn(scheduler);
        }
    }
}
