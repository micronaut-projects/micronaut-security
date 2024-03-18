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
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
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
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * An Authenticator operates on several {@link ReactiveAuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 * @param <T> Request Context Type
 */
@Singleton
public class Authenticator<T> {
    private static final Logger LOG = LoggerFactory.getLogger(Authenticator.class);

    private final List<ReactiveAuthenticationProvider<T, ?, ?>> reactiveAuthenticationProviders;
    private final BeanContext beanContext;

    private final List<AuthenticationProvider<T, ?, ?>> imperativeAuthenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    private final Map<String, Scheduler> executeNameToScheduler = new ConcurrentHashMap<>();

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

    private List<ReactiveAuthenticationProvider<T, ?, ?>> everyProviderSorted() {
        List<ReactiveAuthenticationProvider<T, ?, ?>> providers = new ArrayList<>(reactiveAuthenticationProviders);
        if (beanContext != null) {
            providers.addAll(imperativeAuthenticationProviders.stream()
                    .map(imperativeAuthenticationProvider -> {
                        if (imperativeAuthenticationProvider instanceof ExecutorAuthenticationProvider<?, ?, ?> ap) {
                            return new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider, executeNameToScheduler.computeIfAbsent(ap.getExecutorName(), s ->
                                    beanContext.findBean(ExecutorService.class, Qualifiers.byName(ap.getExecutorName()))
                                            .map(Schedulers::fromExecutorService)
                                            .orElse(null)));
                        } else {
                            return new AuthenticationProviderAdapter<>(imperativeAuthenticationProvider);
                        }
                    }).toList());
        }
        OrderUtil.sort(providers);
        return providers;
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
            AtomicReference<Throwable> lastError = new AtomicReference<>();
            Flux<AuthenticationResponse> authentication = Flux.mergeDelayError(1,  providers.stream()
                    .map(auth -> Flux.from(auth.authenticate(request, authenticationRequest)))
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
