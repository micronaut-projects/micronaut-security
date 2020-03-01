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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.async.publisher.Publishers;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * An implementation of {@link AuthenticationFetcher} that decodes a username
 * and password from the Authorization header and authenticates the credentials
 * against any {@link AuthenticationProvider}s available.
 */
@Requires(property = BasicAuthAuthenticationConfiguration.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Singleton
public class BasicAuthAuthenticationFetcher implements AuthenticationFetcher {

    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthAuthenticationFetcher.class);
    private static final String PREFIX = "Basic ";
    private final Authenticator authenticator;
    private final BasicAuthAuthenticationConfiguration configuration;

    /**
     * @param authenticator The authenticator to authenticate the credentials
     * @param configuration The basic authentication configuration
     */
    public BasicAuthAuthenticationFetcher(Authenticator authenticator,
                                          BasicAuthAuthenticationConfiguration configuration) {
        this.authenticator = authenticator;
        this.configuration = configuration;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        Optional<UsernamePasswordCredentials> credentials = request.getHeaders().getAuthorization()
                .map(s -> s.substring(PREFIX.length()))
                .flatMap(this::decode);

        if (credentials.isPresent()) {
            Flowable<AuthenticationResponse> authenticationResponse = Flowable.fromPublisher(authenticator.authenticate(request, credentials.get()));

            return authenticationResponse.switchMap(response -> {
                if (response.isAuthenticated()) {
                    UserDetails userDetails = response.getUserDetails().get();
                    return Flowable.just(new AuthenticationUserDetailsAdapter(userDetails, configuration.getRolesName()));
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Could not authenticate {}", credentials.get().getUsername());
                    }
                    return Flowable.empty();
                }
            });

        } else {
            return Publishers.empty();
        }
    }

    private Optional<UsernamePasswordCredentials> decode(String credentials) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(credentials);
        } catch (IllegalArgumentException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while trying to Base 64 decode: {}", credentials);
            }
            return Optional.empty();
        }

        String token = new String(decoded, StandardCharsets.UTF_8);

        String[] parts = token.split(":");
        if (parts.length < 2) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Bad format of the basic auth header - Delimiter : not found");
            }
            return Optional.empty();
        }

        return Optional.of(new UsernamePasswordCredentials(parts[0], parts[1]));
    }
}
