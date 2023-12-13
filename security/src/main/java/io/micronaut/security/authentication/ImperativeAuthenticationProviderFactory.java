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

import io.micronaut.context.BeanContext;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import jakarta.inject.Named;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;

/**
 * A factory for adapting {@link ImperativeAuthenticationProvider} beans to expose them as {@link AuthenticationProvider}.
 *
 * @since 4.5.0
 */
@Factory
@Internal
class ImperativeAuthenticationProviderFactory {

    private final Scheduler scheduler;
    private final BeanContext beanContext;

    ImperativeAuthenticationProviderFactory(@Named(TaskExecutors.BLOCKING) ExecutorService executorService,
                                            BeanContext beanContext) {
        this.scheduler = Schedulers.fromExecutorService(executorService);
        this.beanContext = beanContext;
    }

    /**
     * Creates an adapted {@link AuthenticationProvider} for each provided instance of {@link ImperativeAuthenticationProvider}.
     *
     * <p>
     * NOTE - If there are multiple instances of {@link ImperativeAuthenticationProvider} in the application context, then they
     * must be annotated with a {@link jakarta.inject.Qualifier} such as {@link Named}.
     * </p>
     *
     * @param imperativeAuthenticationProvider An instance of {@link ImperativeAuthenticationProvider} to be adapted
     * @return An {@link AuthenticationProvider} adapted from the blocking provider
     * @param <T> The request type
     */
    @EachBean(ImperativeAuthenticationProvider.class)
    <T> AuthenticationProvider<T> createAuthenticationProvider(ImperativeAuthenticationProvider<T> imperativeAuthenticationProvider) {
        return new ImperativeAuthenticationProviderAdapter<>(imperativeAuthenticationProvider,
                ImperativeAuthenticationProviderUtils.isAuthenticateBlocking(beanContext, imperativeAuthenticationProvider) ? scheduler : null);
    }

    private static final class ImperativeAuthenticationProviderAdapter<T> implements AuthenticationProvider<T> {

        @NonNull
        private final ImperativeAuthenticationProvider<T> imperativeAuthenticationProvider;

        @Nullable
        private final Scheduler scheduler;

        private ImperativeAuthenticationProviderAdapter(@NonNull ImperativeAuthenticationProvider<T> imperativeAuthenticationProvider,
                                                      @Nullable Scheduler scheduler) {
            this.imperativeAuthenticationProvider = imperativeAuthenticationProvider;
            this.scheduler = scheduler;
        }

        @Override
        public Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Mono<AuthenticationResponse> authenticationResponseMono = Mono.fromCallable(() -> imperativeAuthenticationProvider.authenticate(httpRequest, authenticationRequest));
            return scheduler != null ? authenticationResponseMono.subscribeOn(scheduler) : authenticationResponseMono;
        }
    }
}
