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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
    @SuppressWarnings("unchecked")
    private static final Flux<AuthenticationResponse>[] EMPTY_FLUX_ARRAY = new Flux[0];

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
        logProviders("Imperative authentication providers", imperativeAuthenticationProviders);
        logProviders("Reactive authentication providers", reactiveAuthenticationProviders);
        if (CollectionUtils.isEmpty(reactiveAuthenticationProviders) && imperativeAuthenticationProviders != null && !anyImperativeAuthenticationProviderIsBlocking()) {
            return Mono.just(authenticate(requestContext, authenticationRequest, imperativeAuthenticationProviders, securityConfiguration));
        }
        return authenticate(requestContext, authenticationRequest, everyProviderSorted());
    }

    private static void logProviders(String description, @Nullable List<?> providers) {
        if (LOG.isDebugEnabled() && providers != null) {
            LOG.debug("{}: {}", description, providers.stream()
                    .map(provider -> provider.getClass().getName())
                    .collect(Collectors.joining(", ")));
        }
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
        logProviders("Authentication providers in provider order", providers);
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {

            return Flux.mergeDelayError(1,
                            providers.stream()
                            .map(provider ->
                                Flux.from(provider.authenticate(request, authenticationRequest))
                                        .switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                                        .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected")))
                            )
                            .toList()
                    .toArray(EMPTY_FLUX_ARRAY))
                    .last()
                    .onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)))
                    .flux();
        }
        return authenticateAny(request, authenticationRequest, providers);
    }

    /**
     * Providers may complete on different threads, so failures are recorded by provider index and, when no provider
     * succeeds, the failure of the first provider in provider order is returned. This mirrors the imperative ANY path.
     * The failures are held per subscription, so subscribing again never observes the failures of an earlier attempt.
     * Each provider is invoked inside a defer so that a provider which throws instead of returning a publisher is
     * recorded as a failure as well.
     * @param request The request context
     * @param authenticationRequest The authentication request
     * @param providers The providers, in provider order
     * @return The first successful response or, if every provider fails, the failure of the first provider
     */
    private Flux<AuthenticationResponse> authenticateAny(T request,
                                                         AuthenticationRequest authenticationRequest,
                                                         List<ReactiveAuthenticationProvider<T, ?, ?>> providers) {
        return Flux.defer(() -> {
            AtomicReferenceArray<AuthenticationResponse> failures = new AtomicReferenceArray<>(providers.size());
            List<Flux<AuthenticationResponse>> attempts = IntStream.range(0, providers.size())
                    .<Flux<AuthenticationResponse>>mapToObj(index -> Flux.defer(() -> Flux.from(providers.get(index).authenticate(request, authenticationRequest)))
                            .switchMap(rsp -> Authenticator.handleResponse((AuthenticationResponse) rsp))
                            .onErrorResume((Function<Throwable, Publisher<AuthenticationResponse>>) t -> {
                                failures.set(index, failedResponseForThrowable(t));
                                return Flux.empty();
                            }))
                    .toList();
            return Flux.mergeDelayError(1, attempts.toArray(EMPTY_FLUX_ARRAY))
                    .take(1)
                    .switchIfEmpty(Mono.fromSupplier(() -> firstFailure(failures)));
        });
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
     * Converts a throwable raised by a provider into an {@link AuthenticationResponse}, on both the imperative and the
     * reactive paths. An {@link AuthenticationException} is a deliberate rejection, so its response, or failing that
     * its message, is returned. Any other throwable is an unexpected error: it is logged and answered with a failure
     * that does not carry the throwable's message, because that message can reach the client in the HTTP response.
     * @param t Throwable raised by a provider
     * @return The failed authentication response
     */
    @NonNull
    private static AuthenticationResponse failedResponseForThrowable(@NonNull Throwable t) {
        if (t instanceof AuthenticationException authenticationException) {
            AuthenticationResponse response = authenticationException.getResponse();
            return response != null ? response : new AuthenticationFailed(authenticationException.getMessage());
        }
        LOG.error("An authentication provider failed with an unexpected error. Authentication rejected", t);
        return AuthenticationResponse.failure();
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
            return failedResponseForThrowable(t);
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
