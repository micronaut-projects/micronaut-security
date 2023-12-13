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
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Named;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.concurrent.ExecutorService;

/**
 * A factory for adapting {@link AuthenticationProvider} beans to expose them as {@link ReactiveAuthenticationProvider}.
 *
 * @since 4.5.0
 */
@Factory
@Internal
class AuthenticationProviderFactory {

    private final Scheduler scheduler;
    private final BeanContext beanContext;

    AuthenticationProviderFactory(@Named(TaskExecutors.BLOCKING) ExecutorService executorService,
                                            BeanContext beanContext) {
        this.scheduler = Schedulers.fromExecutorService(executorService);
        this.beanContext = beanContext;
    }

    /**
     * Creates an adapted {@link AuthenticationProvider} for each provided instance of {@link AuthenticationProvider}.
     *
     * <p>
     * NOTE - If there are multiple instances of {@link AuthenticationProvider} in the application context, then they
     * must be annotated with a {@link jakarta.inject.Qualifier} such as {@link Named}.
     * </p>
     *
     * @param authenticationProvider An instance of {@link AuthenticationProvider} to be adapted
     * @return An {@link AuthenticationProvider} adapted from the blocking provider
     * @param <T> The request type
     */
    @EachBean(AuthenticationProvider.class)
    <T> ReactiveAuthenticationProvider<T> createAuthenticationProvider(AuthenticationProvider<T> authenticationProvider) {
        return new AuthenticationProviderAdapter<>(authenticationProvider,
                AuthenticationProviderUtils.isAuthenticateBlocking(beanContext, authenticationProvider) ? scheduler : null);
    }

    private static final class AuthenticationProviderAdapter<T> implements ReactiveAuthenticationProvider<T> {

        @NonNull
        private final AuthenticationProvider<T> authenticationProvider;

        @Nullable
        private final Scheduler scheduler;

        private AuthenticationProviderAdapter(@NonNull AuthenticationProvider<T> authenticationProvider,
                                                      @Nullable Scheduler scheduler) {
            this.authenticationProvider = authenticationProvider;
            this.scheduler = scheduler;
        }

        @Override
        public Publisher<AuthenticationResponse> authenticate(T httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
            Mono<AuthenticationResponse> authenticationResponseMono = Mono.fromCallable(() -> authenticationProvider.authenticate(httpRequest, authenticationRequest));
            return scheduler != null ? authenticationResponseMono.subscribeOn(scheduler) : authenticationResponseMono;
        }
    }
}
