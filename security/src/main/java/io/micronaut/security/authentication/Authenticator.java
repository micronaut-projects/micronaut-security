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

import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
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

    protected final Collection<AuthenticationProvider<T>> authenticationProviders;

    protected final List<ReactiveAuthenticationProvider<T>> reactiveAuthenticationProviders;
    private final SecurityConfiguration securityConfiguration;

    /**
     * @param authenticationProviders A list of available authentication providers
     * @param securityConfiguration The security configuration
     */
    @Inject
    public Authenticator(List<ReactiveAuthenticationProvider<T>> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.reactiveAuthenticationProviders = authenticationProviders;
        this.securityConfiguration = securityConfiguration;
        this.authenticationProviders = Collections.emptyList();
    }

    /**
     * @param authenticationProviders A list of available authentication providers
     * @param securityConfiguration The security configuration
     * @deprecated Use {@link Authenticator(List, SecurityConfiguration)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.5.0")
    public Authenticator(Collection<AuthenticationProvider<T>> authenticationProviders,
                         SecurityConfiguration securityConfiguration) {
        this.authenticationProviders = authenticationProviders;
        this.reactiveAuthenticationProviders = new ArrayList<>(authenticationProviders);
        this.securityConfiguration = securityConfiguration;
    }

    /**
     * Authenticates the user with the provided credentials.
     *
     * @param request The HTTP request
     * @param authenticationRequest Represents a request to authenticate.
     * @return A publisher that emits {@link AuthenticationResponse} objects
     */
    public Publisher<AuthenticationResponse> authenticate(T request, AuthenticationRequest<?, ?> authenticationRequest) {
        if (this.reactiveAuthenticationProviders == null) {
            return Flux.empty();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(reactiveAuthenticationProviders.stream().map(ReactiveAuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        Flux<AuthenticationResponse>[] emptyArr = new Flux[0];
        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {

            return Flux.mergeDelayError(1,
                    reactiveAuthenticationProviders.stream()
                            .map(provider -> Flux.from(provider.authenticate(request, authenticationRequest))
                                    .switchMap(this::handleResponse)
                                    .switchIfEmpty(Flux.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected"))))
                            .collect(Collectors.toList())
                    .toArray(emptyArr))
                    .last()
                    .onErrorResume(t -> Mono.just(authenticationResponseForThrowable(t)))
                    .flux();
        } else {
            AtomicReference<Throwable> lastError = new AtomicReference<>();
            Flux<AuthenticationResponse> authentication = Flux.mergeDelayError(1,  reactiveAuthenticationProviders.stream()
                    .map(auth -> auth.authenticate(request, authenticationRequest))
                    .map(Flux::from)
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
