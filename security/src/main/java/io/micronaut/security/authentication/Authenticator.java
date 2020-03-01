/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.util.Collection;
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

    /**
     * @param authenticationProviders a List of available authentication providers
     */
    public Authenticator(Collection<AuthenticationProvider> authenticationProviders) {
        this.authenticationProviders = authenticationProviders;
    }

    /**
     * Authenticates the user with the provided credentials.
     *
     * @param request The current request
     * @param authenticationRequest The authentication credentials
     * @return A publisher that emits {@link AuthenticationResponse} objects
     */
    public Publisher<AuthenticationResponse> authenticate(HttpRequest<?> request, AuthenticationRequest<?, ?> authenticationRequest) {
        if (this.authenticationProviders == null) {
            return Flowable.empty();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(authenticationProviders.stream().map(AuthenticationProvider::getClass).map(Class::getName).collect(Collectors.joining()));
        }
        AtomicReference<Throwable> lastError = new AtomicReference<>();

        Flowable<AuthenticationResponse> authentication = Flowable.mergeDelayError(authenticationProviders.stream()
                .map(auth -> auth.authenticate(request, authenticationRequest))
                .map(Flowable::fromPublisher)
                .map(flow -> flow.onErrorResumeNext(t -> {
                    lastError.set(t);
                    return Flowable.empty();
                }))
                .collect(Collectors.toList()));

        return authentication.take(1).switchIfEmpty(Flowable.create((emitter) -> {
            Throwable error = lastError.get();
            if (error != null) {
                emitter.onError(error);
            } else {
                emitter.onComplete();
            }
        }, BackpressureStrategy.ERROR));
    }
}
