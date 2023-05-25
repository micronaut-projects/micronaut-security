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
package io.micronaut.security.token;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.event.TokenValidatedEvent;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.token.reader.TokenResolver;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.Optional;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

/**
 * Attempts to retrieve a token form the {@link HttpRequest} and if existing validated.
 * It uses a {@link TokenResolver} and the list of {@link TokenValidator} registered in the ApplicationContext.
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
public class TokenAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

    /**
     * The order of the fetcher.
     */
    public static final Integer ORDER = 0;

    protected final Collection<TokenValidator<HttpRequest<?>>> tokenValidators;
    protected final ApplicationEventPublisher<TokenValidatedEvent> tokenValidatedEventPublisher;
    private final TokenResolver<HttpRequest<?>> tokenResolver;

    /**
     * @param tokenValidators The list of {@link TokenValidator} which attempt to validate the request
     * @param tokenResolver   The {@link io.micronaut.security.token.reader.TokenResolver} which returns the first found token in the request.
     * @param tokenValidatedEventPublisher Application event publisher for {@link TokenValidatedEvent}.
     */
    public TokenAuthenticationFetcher(Collection<TokenValidator<HttpRequest<?>>> tokenValidators,
                                      TokenResolver<HttpRequest<?>> tokenResolver,
                                      ApplicationEventPublisher<TokenValidatedEvent> tokenValidatedEventPublisher) {
        this.tokenValidatedEventPublisher = tokenValidatedEventPublisher;
        this.tokenResolver = tokenResolver;
        this.tokenValidators = tokenValidators;
    }

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {

        Optional<String> token = tokenResolver.resolveToken(request);

        if (!token.isPresent()) {
            return Flux.empty();
        }

        String tokenValue = token.get();

        return Flux.fromIterable(tokenValidators)
                .flatMap(tokenValidator -> tokenValidator.validateToken(tokenValue, request))
                .next()
                .map(authentication -> {
                    request.setAttribute(TOKEN, tokenValue);
                    tokenValidatedEventPublisher.publishEvent(new TokenValidatedEvent(tokenValue));
                    return authentication;
                });
    }

    @Override
    public int getOrder() {
        return ORDER;
    }
}
