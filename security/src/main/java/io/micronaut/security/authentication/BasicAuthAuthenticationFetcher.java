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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Singleton;
import java.util.Optional;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Flux;

/**
 * An implementation of {@link AuthenticationFetcher} that decodes a username
 * and password from the Authorization header and authenticates the credentials
 * against any {@link io.micronaut.security.authentication.provider.ReactiveAuthenticationProvider}s available.
 * @param <B> The HTTP Request Body type
 */
@Requires(classes = HttpRequest.class)
@Requires(property = BasicAuthAuthenticationConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Singleton
public class BasicAuthAuthenticationFetcher<B> implements AuthenticationFetcher<HttpRequest<B>> {

    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticationFetcher.class);
    private final Authenticator<HttpRequest<B>> authenticator;

    /**
     * @param authenticator The authenticator to authenticate the credentials
     */
    public BasicAuthAuthenticationFetcher(Authenticator<HttpRequest<B>> authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<B> request) {
        Optional<UsernamePasswordCredentials> credentials = request.getHeaders().getAuthorization().flatMap(BasicAuthUtils::parseCredentials);

        if (credentials.isPresent()) {
            Flux<AuthenticationResponse> authenticationResponse = Flux.from(authenticator.authenticate(request, credentials.get()));

            return authenticationResponse.switchMap(response -> {
                if (response.isAuthenticated() && response.getAuthentication().isPresent()) {
                    return Flux.just(response.getAuthentication().get());
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Could not authenticate {}", credentials.get().getUsername());
                    }
                    return Publishers.empty();
                }
            });

        } else {
            return Publishers.empty();
        }
    }
}
