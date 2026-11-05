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
import io.micronaut.context.annotation.Requires;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.core.util.StringUtils;
import io.micronaut.inject.BeanDefinition;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.ExecutorAuthenticationProvider;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * An Authenticator operates on several {@link ReactiveAuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
 *
 * <p>Providers are evaluated one at a time in {@link io.micronaut.core.order.Ordered} precedence order. With the default
 * {@link AuthenticationStrategy#ANY} strategy the response of the highest precedence provider that authenticates the
 * request wins, regardless of how fast lower precedence providers answer, and lower precedence providers are not
 * subscribed to once a provider has authenticated the request.</p>
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 * @param <T> Request Context Type
 */
@Requires(condition = AuthenticatorCondition.class)
@Singleton
public class Authenticator<T> {
    private static final Logger LOG = LoggerFactory.getLogger(Authenticator.class);
    private static final String AUTHENTICATE_METHOD_NAME = "authenticate";

    private final List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders;
    private final BeanContext beanContext;

    private final List<AuthenticationProvider<T, ?, ?>> imperativeAuthenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    private final Map<String, Scheduler> executeNameToScheduler = new ConcurrentHashMap<>();

    private final Map<Class<?>, Boolean> blockingAnnotatedProviderClasses = new ConcurrentHashMap<>();

    /**
     * @param beanContext Bean Context
     * @param reactiveAuthenticationProviders A list of available Reactive authentication providers
     * @param authenticationProviders A list of available imperative authentication providers
     * @param securityConfiguration The security configuration
     */
    public Authenticator(BeanContext beanContext,
                         List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders,
                         List<AuthenticationProvider<T, ?, ?>> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.beanContext = beanContext;
        this.reactiveAuthenticationProviders = reactiveAuthenticationProviders;
        this.securityConfiguration = securityConfiguration;
        this.imperativeAuthenticationProviders = authenticationProviders;
    }

    /**
     * Authenticates the user with the provided credentials.
     *
     * @param requestContext           The HTTP request
     * @param authenticationRequest Represents a request to authenticate.
     * @return A publisher that emits {@link AuthenticationResponse} objects
     */
    public Publisher<AuthenticationResponse> authenticate(T requestContext, AuthenticationRequest<?, ?> authenticationRequest) {
        if (CollectionUtils.isEmpty(reactiveAuthenticationProviders) && CollectionUtils.isEmpty(imperativeAuthenticationProviders)) {
            return Mono.empty();
        }
        if (LOG.isDebugEnabled() && imperativeAuthenticationProviders != null) {
            LOG.debug(imperativeAuthenticationProviders.stream().map(AuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        if (LOG.isDebugEnabled() && reactiveAuthenticationProviders != null) {
            LOG.debug(reactiveAuthenticationProviders.stream().map(ReactiveAuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        if (CollectionUtils.isEmpty(reactiveAuthenticationProviders) && imperativeAuthenticationProviders != null && !anyImperativeAuthenticationProviderIsBlocking()) {
            return Mono.just(authenticate(requestContext, authenticationRequest, imperativeAuthenticationProviders, securityConfiguration));
        }
        return authenticate(requestContext, authenticationRequest, everyProviderSorted());
    }

    /**
     *
     * @return Whether any of the authentication provider is blocking
     */
    private boolean anyImperativeAuthenticationProviderIsBlocking() {
        return imperativeAuthenticationProviders.stream().anyMatch(this::isImperativeAuthenticationProviderIsBlocking);
    }

    /**
     * Returns {@code true} if the authentication provider is an {@link ExecutorAuthenticationProvider}, whatever the
     * executor it names via {@link ExecutorAuthenticationProvider#getExecutorName()}, or if its {@code authenticate}
     * method or its class is annotated with {@link Blocking}. Such providers declare that they block, so they are never
     * invoked on the thread that subscribes to the authentication publisher (for example the Netty event loop). Executor
     * providers are subscribed on the executor they name; {@link Blocking} providers on the {@code blocking} executor.
     * <p>
     * The {@link Blocking} annotation is read from the compile-time bean definition metadata, so it is only honoured for
     * providers created by the bean context (not for instances registered at runtime or constructed by hand).
     * @param authenticationProvider An authentication provider
     * @return Whether the authentication provider is blocking.
     */
    protected boolean isImperativeAuthenticationProviderIsBlocking(AuthenticationProvider<?, ?, ?> authenticationProvider) {
        return authenticationProvider instanceof ExecutorAuthenticationProvider || isAnnotatedBlocking(authenticationProvider);
    }

    private boolean isAnnotatedBlocking(@NonNull AuthenticationProvider<?, ?, ?> authenticationProvider) {
        if (beanContext == null) {
            return false;
        }
        return blockingAnnotatedProviderClasses.computeIfAbsent(authenticationProvider.getClass(), this::isAnnotatedBlocking);
    }

    /**
     * Inspects the bean definitions of the given provider class, without reflection: {@code authenticate} is
     * {@link io.micronaut.context.annotation.Executable} on {@link AuthenticationProvider}, so every implementation's
     * {@code authenticate} method is available as an {@link io.micronaut.inject.ExecutableMethod} with its annotations.
     * @param providerClass The authentication provider class
     * @return Whether the class, or any of its {@code authenticate} methods, is annotated with {@link Blocking}
     */
    private boolean isAnnotatedBlocking(@NonNull Class<?> providerClass) {
        return beanContext.getBeanDefinitions(providerClass).stream().anyMatch(Authenticator::isAnnotatedBlocking);
    }

    private static boolean isAnnotatedBlocking(@NonNull BeanDefinition<?> definition) {
        return definition.getAnnotationMetadata().hasAnnotation(Blocking.class)
            || definition.findPossibleMethods(AUTHENTICATE_METHOD_NAME).anyMatch(method -> method.hasAnnotation(Blocking.class));
    }

    @NonNull
    private AuthenticationResponse authenticate(@NonNull T requestContext,
                                                @NonNull AuthenticationRequest<?, ?> authenticationRequest,
                                                @NonNull List<AuthenticationProvider<T, ?, ?>> authenticationProviders,
                                                @Nullable SecurityConfiguration securityConfiguration) {
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {
            return authenticateAll(requestContext, authenticationRequest, authenticationProviders);
        }
        List<AuthenticationResponse> responses = new ArrayList<>();
        for (AuthenticationProvider<T, ?, ?> provider : authenticationProviders) {
            AuthenticationResponse response = authenticationResponse(provider, requestContext, authenticationRequest);
            if (response.isAuthenticated()) {
                return response;
            }
            responses.add(response);
        }
        return responses.stream()
                        .findFirst()
                        .orElseGet(AuthenticationResponse::failure);
    }

    @NonNull
    private AuthenticationResponse authenticateAll(@NonNull T requestContext,
                                                   @NonNull AuthenticationRequest<?, ?> authenticationRequest,
                                                   @NonNull List<AuthenticationProvider<T, ?, ?>> authenticationProviders) {
        List<AuthenticationResponse> authenticationResponses = authenticationProviders.stream()
                        .map(provider -> authenticationResponse(provider, requestContext, authenticationRequest))
                        .toList();
        if (CollectionUtils.isEmpty(authenticationResponses)) {
            return AuthenticationResponse.failure();
        }
        return authenticationResponses.stream().allMatch(AuthenticationResponse::isAuthenticated)
                ? authenticationResponses.get(0)
                : AuthenticationResponse.failure();
    }

    private List<ReactiveAuthenticationProvider<T, ?, ?>> everyProviderSorted() {
        List<ReactiveAuthenticationProvider<T, ?, ?>> providers = new ArrayList<>(reactiveAuthenticationProviders);
        if (beanContext != null) {
            providers.addAll(imperativeAuthenticationProviders.stream()
                    .map(imperativeAuthenticationProvider -> {
                        if (imperativeAuthenticationProvider instanceof ExecutorAuthenticationProvider<?, ?, ?> ap) {
                            return new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider, schedulerFor(ap));
                        } else if (isAnnotatedBlocking(imperativeAuthenticationProvider)) {
                            return new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider, schedulerFor(imperativeAuthenticationProvider, TaskExecutors.BLOCKING));
                        } else {
                            return new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider);
                        }
                    }).toList());
        }
        OrderUtil.sort(providers);
        return providers;
    }

    /**
     * Resolves the {@link Scheduler} on which an {@link ExecutorAuthenticationProvider} is subscribed. A blocking
     * provider must never run on the subscribing thread, so when no {@link ExecutorService} bean matches the executor
     * name the provider declares, the {@link TaskExecutors#BLOCKING} executor is used instead and a warning is logged.
     * @param authenticationProvider An executor authentication provider
     * @return The scheduler backed by the executor the provider names, or by the blocking executor as a fallback
     */
    @NonNull
    private Scheduler schedulerFor(@NonNull ExecutorAuthenticationProvider<?, ?, ?> authenticationProvider) {
        return schedulerFor(authenticationProvider, authenticationProvider.getExecutorName());
    }

    @NonNull
    private Scheduler schedulerFor(@NonNull AuthenticationProvider<?, ?, ?> authenticationProvider, @Nullable String executorName) {
        if (StringUtils.isEmpty(executorName)) {
            executorName = TaskExecutors.BLOCKING;
        }
        return executeNameToScheduler.computeIfAbsent(executorName, name -> findScheduler(name).orElseGet(() -> {
            LOG.warn("No ExecutorService bean named '{}' found for authentication provider {}. Falling back to the '{}' executor so that the blocking provider does not run on the event loop.",
                name, authenticationProvider.getClass().getName(), TaskExecutors.BLOCKING);
            return findScheduler(TaskExecutors.BLOCKING).orElseGet(Schedulers::boundedElastic);
        }));
    }

    @NonNull
    private Optional<Scheduler> findScheduler(@NonNull String executorName) {
        return beanContext.findBean(ExecutorService.class, Qualifiers.byName(executorName))
                .map(Schedulers::fromExecutorService);
    }

    private Publisher<AuthenticationResponse> authenticate(T request,
                                                           AuthenticationRequest authenticationRequest,
                                                           List<ReactiveAuthenticationProvider<T, ?, ?>> providers) {
        if (providers == null) {
            return Flux.empty();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(providers.stream().map(ReactiveAuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        Flux<AuthenticationResponse>[] emptyArr = new Flux[0];
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {

            return Flux.concatDelayError(
                            providers.stream()
                            .map(provider ->
                                Flux.defer(() -> provider.authenticate(request, authenticationRequest))
                                        .switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                                        .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected")))
                            )
                            .toList()
                    .toArray(emptyArr))
                    .collectList()
                    .filter(responses -> !responses.isEmpty())
                    .map(responses -> responses.get(0))
                    .onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)))
                    .flux();
        } else {
            AtomicReference<Throwable> lastError = new AtomicReference<>();
            // Subscribe to the providers sequentially in precedence order. Merging them would let the fastest
            // provider win instead of the highest precedence provider that accepts the credentials.
            Flux<AuthenticationResponse> authentication = Flux.concat(providers.stream()
                    .map(auth -> Flux.defer(() -> auth.authenticate(request, authenticationRequest)))
                    .map(sequence -> sequence.switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                            .onErrorResume((Function<Throwable, Publisher>) t -> {
                                lastError.set(t);
                                return Flux.empty();
                            })
                            ).toList()
                    .toArray(emptyArr));

            return authentication.take(1)
                    .switchIfEmpty(Flux.create(emitter -> {
                Throwable error = lastError.get();
                if (error != null) {
                    if (error instanceof AuthenticationException) {
                        AuthenticationResponse response = ((AuthenticationException) error).getResponse();
                        if (response != null) {
                            emitter.next(response);
                            emitter.complete();
                        } else {
                            emitter.error(error);
                        }
                    } else {
                        emitter.error(error);
                    }
                } else {
                    emitter.complete();
                }
            }, FluxSink.OverflowStrategy.ERROR));
        }
    }

    private static Mono<AuthenticationResponse> handleResponse(AuthenticationResponse response) {
        if (response.isAuthenticated()) {
            return Mono.just(response);
        } else {
            return Mono.error(new AuthenticationException(response));
        }
    }

    @NonNull
    private AuthenticationResponse authenticationResponse(@NonNull AuthenticationProvider<T, ?, ?> provider,
                                                          @NonNull T requestContext,
                                                          @NonNull AuthenticationRequest authenticationRequest) {
        try {
            return provider.authenticate(requestContext, authenticationRequest);
        } catch (Exception t) {
            return authenticationResponseForThrowable(t);
        }
    }

    @NonNull
    private static AuthenticationResponse authenticationResponseForThrowable(Throwable t) {
        if (Exceptions.isMultiple(t)) {
            List<Throwable> exceptions = Exceptions.unwrapMultiple(t);
            return new AuthenticationFailed(exceptions.get(exceptions.size() - 1).getMessage());
        }
        return new AuthenticationFailed(t.getMessage());
    }

}
