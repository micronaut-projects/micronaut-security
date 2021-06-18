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

import io.micronaut.http.HttpRequest;
import io.reactivex.BackpressureStrategy;
import io.micronaut.security.config.AuthenticationStrategy;
import io.micronaut.security.config.SecurityConfiguration;
import io.reactivex.Flowable;
import io.reactivex.exceptions.CompositeException;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * An Authenticator operates on several {@link AuthenticationProvider} instances returning the first
 * authenticated {@link AuthenticationResponse}.
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
        this.authenticationProviders = authenticationProviders;
        this.securityConfiguration = securityConfiguration;
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
            return Flowable.empty();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(authenticationProviders.stream().map(AuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }

        if (securityConfiguration != null && securityConfiguration.getAuthenticationProviderStrategy() == AuthenticationStrategy.ALL) {
            return Flowable.mergeDelayError(
                    authenticationProviders.stream()
                            .map(provider -> {
                                return Flowable.fromPublisher(provider.authenticate(request, authenticationRequest))
                                        .switchMap(response -> {
                                            if (response.isAuthenticated()) {
                                                return Flowable.just(response);
                                            } else {
                                                return Flowable.error(() -> new AuthenticationException(response));
                                            }
                                        })
                                        .switchIfEmpty(Flowable.error(() -> new AuthenticationException("Provider did not respond. Authentication rejected")));
                            })
                            .collect(Collectors.toList()))
                    .lastOrError()
                    .onErrorReturn((t) -> {
                        if (t instanceof CompositeException) {
                            List<Throwable> exceptions = ((CompositeException) t).getExceptions();
                            return new AuthenticationFailed(exceptions.get(exceptions.size() - 1).getMessage());
                        } else {
                            return new AuthenticationFailed(t.getMessage());
                        }
                    })
                    .toFlowable();
        } else {
            AtomicReference<Throwable> lastError = new AtomicReference<>();

            Flowable<AuthenticationResponse> authentication = Flowable.mergeDelayError(authenticationProviders.stream()
                    .map(auth -> auth.authenticate(request, authenticationRequest))
                    .map(Flowable::fromPublisher)
                    .map(flow ->
                        flow.switchMap(response -> {
                            if (response.isAuthenticated()) {
                                return Flowable.just(response);
                            } else {
                                return Flowable.error(new AuthenticationException(response));
                            }
                        }).onErrorResumeNext(t -> {
                            lastError.set(t);
                            return Flowable.empty();
                        })
                    )
                    .collect(Collectors.toList()));

            return authentication.take(1).switchIfEmpty(Flowable.create((emitter) -> {
                Throwable error = lastError.get();
                if (error != null) {
                    if (error instanceof AuthenticationException) {
                        AuthenticationResponse response = ((AuthenticationException) error).getResponse();
                        if (response != null) {
                            emitter.onNext(response);
                            emitter.onComplete();
                        } else {
                            emitter.onError(error);
                        }
                    } else {
                        emitter.onError(error);
                    }
                } else {
                    emitter.onComplete();
                }
            }, BackpressureStrategy.ERROR));
        }
    }

}
