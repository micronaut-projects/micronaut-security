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
import io.micronaut.context.exceptions.ConfigurationException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.core.util.CollectionUtils;
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
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * An Authenticator operates on several {@link ReactiveAuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
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

    private final List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders;

    private final List<AuthenticationProvider<T, ?, ?>> imperativeAuthenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    /**
     * Every provider, reactive and imperative (adapted to reactive), sorted by order. Built once at construction time so
     * that no adapter is created, no list sorted and no executor bean looked up per authentication.
     */
    private final List<ReactiveAuthenticationProvider<T, ?, ?>> everyProviderSorted;

    /**
     * @param beanContext Bean Context
     * @param reactiveAuthenticationProviders A list of available Reactive authentication providers
     * @param authenticationProviders A list of available imperative authentication providers
     * @param securityConfiguration The security configuration
     * @throws ConfigurationException if an {@link ExecutorAuthenticationProvider} names an executor for which no {@link ExecutorService} bean exists
     */
    public Authenticator(BeanContext beanContext,
                         List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders,
                         List<AuthenticationProvider<T, ?, ?>> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.reactiveAuthenticationProviders = reactiveAuthenticationProviders;
        this.securityConfiguration = securityConfiguration;
        this.imperativeAuthenticationProviders = authenticationProviders;
        this.everyProviderSorted = everyProviderSorted(beanContext, reactiveAuthenticationProviders, authenticationProviders);
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
        return authenticate(requestContext, authenticationRequest, everyProviderSorted);
    }

    /**
     *
     * @return Whether any of the authentication provider is blocking
     */
    private boolean anyImperativeAuthenticationProviderIsBlocking() {
        return imperativeAuthenticationProviders.stream().anyMatch(this::isImperativeAuthenticationProviderIsBlocking);
    }

    /**
     * If {@link ExecutorAuthenticationProvider#getExecutorName()} equals `blocking` or `io` returns `true`.
     * @param authenticationProvider An authentication provider
     * @return Whether any of the authentication provider is blocking.
     */
    protected boolean isImperativeAuthenticationProviderIsBlocking(AuthenticationProvider<?, ?, ?> authenticationProvider) {
        return authenticationProvider instanceof ExecutorAuthenticationProvider ap && (ap.getExecutorName().equals(TaskExecutors.BLOCKING) || ap.getExecutorName().equals(TaskExecutors.IO));
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

    /**
     * Builds the full provider chain: every reactive provider plus every imperative provider adapted to
     * {@link ReactiveAuthenticationProvider}, sorted by order. An {@link ExecutorAuthenticationProvider} is subscribed
     * on a {@link Scheduler} backed by the {@link ExecutorService} bean named by {@link ExecutorAuthenticationProvider#getExecutorName()};
     * the bean is resolved once per executor name.
     * @param beanContext Bean Context used to resolve executor beans
     * @param reactiveAuthenticationProviders Reactive authentication providers
     * @param imperativeAuthenticationProviders Imperative authentication providers
     * @param <T> Request Context Type
     * @return An unmodifiable list with every provider sorted by order
     * @throws ConfigurationException if an {@link ExecutorAuthenticationProvider} names an executor for which no {@link ExecutorService} bean exists
     */
    @NonNull
    private static <T> List<ReactiveAuthenticationProvider<T, ?, ?>> everyProviderSorted(@Nullable BeanContext beanContext,
                                                                                         @Nullable List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders,
                                                                                         @Nullable List<AuthenticationProvider<T, ?, ?>> imperativeAuthenticationProviders) {
        List<ReactiveAuthenticationProvider<T, ?, ?>> providers = new ArrayList<>();
        if (reactiveAuthenticationProviders != null) {
            providers.addAll(reactiveAuthenticationProviders);
        }
        if (beanContext != null && imperativeAuthenticationProviders != null) {
            Map<String, Scheduler> executorNameToScheduler = new HashMap<>();
            for (AuthenticationProvider<T, ?, ?> imperativeAuthenticationProvider : imperativeAuthenticationProviders) {
                if (imperativeAuthenticationProvider instanceof ExecutorAuthenticationProvider<?, ?, ?> ap) {
                    String executorName = ap.getExecutorName();
                    Scheduler scheduler = executorNameToScheduler.computeIfAbsent(executorName, name ->
                            beanContext.findBean(ExecutorService.class, Qualifiers.byName(name))
                                    .map(Schedulers::fromExecutorService)
                                    .orElseThrow(() -> new ConfigurationException("Authentication provider " + ap.getClass().getName()
                                            + " names executor '" + name + "' but no bean of type " + ExecutorService.class.getName()
                                            + " named '" + name + "' exists")));
                    providers.add(new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider, scheduler));
                } else {
                    providers.add(new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider));
                }
            }
        }
        OrderUtil.sort(providers);
        return Collections.unmodifiableList(providers);
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

            return Flux.mergeDelayError(1,
                            providers.stream()
                            .map(provider ->
                                Flux.from(provider.authenticate(request, authenticationRequest))
                                        .switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                                        .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected")))
                            )
                            .toList()
                    .toArray(emptyArr))
                    .last()
                    .onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)))
                    .flux();
        } else {
            // Providers may complete on different threads, so failures are recorded by provider index and, when no
            // provider succeeds, the failure of the first provider in provider order is returned. This mirrors the
            // imperative ANY path.
            AtomicReferenceArray<AuthenticationResponse> failures = new AtomicReferenceArray<>(providers.size());
            Flux<AuthenticationResponse> authentication = Flux.mergeDelayError(1, IntStream.range(0, providers.size())
                    .mapToObj(index -> Flux.from(providers.get(index).authenticate(request, authenticationRequest))
                            .switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                            .onErrorResume((Function<Throwable, Publisher<AuthenticationResponse>>) t -> {
                                failures.set(index, failedResponseForThrowable(t));
                                return Flux.empty();
                            }))
                    .toList()
                    .toArray(emptyArr));

            return authentication.take(1)
                    .switchIfEmpty(Mono.fromSupplier(() -> firstFailure(failures)));
        }
    }

    @Nullable
    private static AuthenticationResponse firstFailure(@NonNull AtomicReferenceArray<AuthenticationResponse> failures) {
        for (int i = 0; i < failures.length(); i++) {
            AuthenticationResponse failure = failures.get(i);
            if (failure != null) {
                return failure;
            }
        }
        return null;
    }

    /**
     * Converts a throwable raised by a provider in the ANY strategy into an {@link AuthenticationResponse}.
     * An {@link AuthenticationException} carrying a response yields that response; any other throwable yields an
     * {@link AuthenticationFailed}, as the imperative path does when a provider throws.
     * @param t Throwable raised by a provider
     * @return The failed authentication response
     */
    @NonNull
    private static AuthenticationResponse failedResponseForThrowable(@NonNull Throwable t) {
        if (t instanceof AuthenticationException authenticationException && authenticationException.getResponse() != null) {
            return authenticationException.getResponse();
        }
        return authenticationResponseForThrowable(t);
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
