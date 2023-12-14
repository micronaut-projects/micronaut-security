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
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.provider.AuthenticationProvider;
import io.micronaut.security.authentication.provider.AuthenticationProviderAdapter;
import io.micronaut.security.authentication.provider.AuthenticationProviderUtils;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import jakarta.inject.Inject;
import jakarta.inject.Named;
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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * An Authenticator operates on several {@link ReactiveAuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 * @param <T> Request
 */
@Singleton
public class Authenticator<T> {

    private static final Logger LOG = LoggerFactory.getLogger(Authenticator.class);

    /**
     *
     * @deprecated Unused. To be removed in the next major version.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    protected final Collection<io.micronaut.security.authentication.AuthenticationProvider<T>> authenticationProviders;

    private final List<ReactiveAuthenticationProvider<T>> reactiveAuthenticationProviders;

    private final BeanContext beanContext;
    private final List<AuthenticationProvider<T>> imperativeAuthenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    private final Scheduler scheduler;

    /**
     * @param beanContext Bean Context
     * @param reactiveAuthenticationProviders A list of available Reactive authentication providers
     * @param authenticationProviders A list of available imperative authentication providers
     * @param executorService BLOCKING executor service
     * @param securityConfiguration The security configuration
     */
    @Inject
    public Authenticator(BeanContext beanContext,
                         List<ReactiveAuthenticationProvider<T>> reactiveAuthenticationProviders,
                         List<AuthenticationProvider<T>> authenticationProviders,
                         @Named(TaskExecutors.BLOCKING) ExecutorService executorService,
                         SecurityConfiguration securityConfiguration) {
        this.beanContext = beanContext;
        this.reactiveAuthenticationProviders = reactiveAuthenticationProviders;
        this.securityConfiguration = securityConfiguration;
        this.imperativeAuthenticationProviders = authenticationProviders;
        this.scheduler = Schedulers.fromExecutorService(executorService);
        this.authenticationProviders = Collections.emptyList();
    }

    /**
     * @param authenticationProviders A list of available authentication providers
     * @param securityConfiguration   The security configuration
     * @deprecated Use {@link Authenticator#Authenticator(BeanContext, List, List, ExecutorService, SecurityConfiguration)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    public Authenticator(Collection<io.micronaut.security.authentication.AuthenticationProvider<T>> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.beanContext = null;
        this.authenticationProviders = authenticationProviders;
        this.reactiveAuthenticationProviders = new ArrayList<>(authenticationProviders);
        this.securityConfiguration = securityConfiguration;
        this.scheduler = null;
        this.imperativeAuthenticationProviders = Collections.emptyList();
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
            return handleResponse(authenticate(requestContext, authenticationRequest, imperativeAuthenticationProviders, securityConfiguration));
        }
        return authenticate(requestContext, authenticationRequest, everyProviderSorted());
    }

    private boolean anyImperativeAuthenticationProviderIsBlocking() {
        return imperativeAuthenticationProviders.stream().anyMatch(provider -> AuthenticationProviderUtils.isAuthenticateBlocking(beanContext, provider));
    }

    @NonNull
    private static <T> AuthenticationResponse authenticate(@NonNull T requestContext,
                                                           @NonNull AuthenticationRequest<?, ?> authenticationRequest,
                                                           @NonNull List<AuthenticationProvider<T>> authenticationProviders,
                                                           @Nullable SecurityConfiguration securityConfiguration) {
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {
            return authenticateAll(requestContext, authenticationRequest, authenticationProviders);
        }
        return authenticationProviders.stream()
                .map(provider -> authenticationResponse(provider, requestContext, authenticationRequest))
                .filter(AuthenticationResponse::isAuthenticated)
                .findFirst()
                .orElseGet(AuthenticationResponse::failure);
    }

    @NonNull
    private static <T> AuthenticationResponse authenticateAll(@NonNull T requestContext,
                                                                         @NonNull AuthenticationRequest<?, ?> authenticationRequest,
                                                                         @NonNull List<AuthenticationProvider<T>> authenticationProviders) {
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

    private List<ReactiveAuthenticationProvider<T>> everyProviderSorted() {
        List<ReactiveAuthenticationProvider<T>> providers = new ArrayList<>(reactiveAuthenticationProviders);
        if (beanContext != null) {
            providers.addAll(imperativeAuthenticationProviders.stream()
                    .map(imperativeAuthenticationProvider -> new AuthenticationProviderAdapter<>(beanContext, scheduler, imperativeAuthenticationProvider)).toList());
        }
        OrderUtil.sort(providers);
        return providers;
    }

    private Publisher<AuthenticationResponse> authenticate(T request,
                                                           AuthenticationRequest<?, ?> authenticationRequest,
                                                           List<ReactiveAuthenticationProvider<T>> providers) {
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
                            .map(provider -> Flux.from(provider.authenticate(request, authenticationRequest))
                                    .switchMap(Authenticator::handleResponse)
                                    .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected"))))
                            .toList()
                    .toArray(emptyArr))
                    .last()
                    .onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)))
                    .flux();
        } else {
            AtomicReference<Throwable> lastError = new AtomicReference<>();
            Flux<AuthenticationResponse> authentication = Flux.mergeDelayError(1,  providers.stream()
                    .map(auth -> auth.authenticate(request, authenticationRequest))
                    .map(Flux::from)
                    .map(sequence -> sequence.switchMap(Authenticator::handleResponse).onErrorResume(t -> {
                        lastError.set(t);
                        return Flux.empty();
                    })).toList()
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
    private static <T> AuthenticationResponse authenticationResponse(@NonNull AuthenticationProvider<T> provider,
                                                                     @NonNull T requestContext,
                                                                     @NonNull AuthenticationRequest<?, ?> authenticationRequest) {
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
