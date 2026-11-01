/*
 * Copyright 2017-2020 original authors
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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.order.OrderUtil;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Mono;

/**
 * An Authenticator operates on several {@link AuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
 *
 * <p>Providers are evaluated one at a time in precedence order: providers implementing {@link io.micronaut.core.order.Ordered}
 * first, by {@code getOrder()}, then the other providers in the order they are injected (which honours {@code @Order}). With the default {@link AuthenticationStrategy#ANY} strategy the
 * response of the highest precedence provider that authenticates the request wins, regardless of how fast lower precedence
 * providers answer, and lower precedence providers are not subscribed to once a provider has authenticated the request.</p>
 *
 * <p>Providers are evaluated one at a time in {@link io.micronaut.core.order.Ordered} precedence order. With the default
 * {@link AuthenticationStrategy#ANY} strategy the response of the highest precedence provider that authenticates the
 * request wins, regardless of how fast lower precedence providers answer, and lower precedence providers are not
 * subscribed to once a provider has authenticated the request.</p>
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Singleton
public class Authenticator {

    private static final Logger LOG = LoggerFactory.getLogger(Authenticator.class);

    protected final Collection<AuthenticationProvider> authenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    /**
     * @param authenticationProviders A list of available authentication providers
     * @param securityConfiguration The security configuration
     */
    public Authenticator(Collection<AuthenticationProvider> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.authenticationProviders = sortedByPrecedence(authenticationProviders);
        this.securityConfiguration = securityConfiguration;
    }

    /**
     * Sorts the providers by precedence. Providers implementing {@link io.micronaut.core.order.Ordered} come first, by
     * {@code getOrder()}; the other providers follow in the order they were given.
     *
     * @param authenticationProviders The providers, possibly {@code null}
     * @return The providers sorted by precedence, or {@code null} if none were given
     */
    private static List<AuthenticationProvider> sortedByPrecedence(Collection<AuthenticationProvider> authenticationProviders) {
        if (authenticationProviders == null) {
            return null;
        }
        List<AuthenticationProvider> sorted = new ArrayList<>(authenticationProviders);
        OrderUtil.sort(sorted);
        return sorted;
    }

    /**
     * Authenticates the user with the provided credentials.
     *
     * @param request The HTTP request
     * @param authenticationRequest Represents a request to authenticate.
     * @return A publisher that emits {@link AuthenticationResponse} objects
     */
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> request, AuthenticationRequest<?, ?> authenticationRequest) {
        if (this.authenticationProviders == null) {
            return Flux.empty();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(authenticationProviders.stream().map(AuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        Flux<AuthenticationResponse>[] emptyArr = new Flux[0];
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {

            return Flux.concatDelayError(
                    authenticationProviders.stream()
                            .map(provider -> Flux.defer(() -> provider.authenticate(request, authenticationRequest))
                                    .switchMap(this::handleResponse)
                                    .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected"))))
                            .collect(Collectors.toList())
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
            Flux<AuthenticationResponse> authentication = Flux.concat(authenticationProviders.stream()
                    .map(auth -> Flux.defer(() -> auth.authenticate(request, authenticationRequest)))
                    .map(sequence -> sequence.switchMap(this::handleResponse).onErrorResume(t -> {
                        lastError.set(t);
                        return Flux.empty();
                    })).collect(Collectors.toList())
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

    private Flux<AuthenticationResponse> handleResponse(AuthenticationResponse response) {
        if (response.isAuthenticated()) {
            return Flux.just(response);
        } else {
            return Flux.error(new AuthenticationException(response));
        }
    }

    @NonNull
    private AuthenticationResponse authenticationResponseForThrowable(Throwable t) {
        if (Exceptions.isMultiple(t)) {
            List<Throwable> exceptions = Exceptions.unwrapMultiple(t);
            return new AuthenticationFailed(exceptions.get(exceptions.size() - 1).getMessage());
        }
        return new AuthenticationFailed(t.getMessage());
    }

}
