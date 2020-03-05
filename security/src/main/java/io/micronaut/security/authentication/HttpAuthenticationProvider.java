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

import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.http.HttpRequest;
import org.reactivestreams.Publisher;

/**
 * Authenticates the authentication request within the context of
 * an http request.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
public interface HttpAuthenticationProvider extends AuthenticationProvider {

    @Override
    default Publisher<AuthenticationResponse> authenticate(AuthenticationRequest authenticationRequest) {
        return Publishers.just(new UnsupportedOperationException("This authentication provider requires the request context"));
    }

    /**
     * Authenticates a user with the given request. If a successful authentication is
     * returned, the object must be an instance of {@link UserDetails}.
     *
     * @param request The HTTP request
     * @param authenticationRequest The request to authenticate
     * @return A publisher that emits 0 or 1 responses
     */
    Publisher<AuthenticationResponse> authenticate(HttpRequest<?> request, AuthenticationRequest<?, ?> authenticationRequest);
}
