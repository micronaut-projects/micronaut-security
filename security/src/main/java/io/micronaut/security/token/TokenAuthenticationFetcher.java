/*
 * Copyright 2017-2024 original authors
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

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.server.util.HttpHostResolver;
import io.micronaut.http.server.util.locale.HttpLocaleResolver;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.context.ServerRequestContextSecurityContextSupplier;
import io.micronaut.security.event.TokenValidatedEvent;
import io.micronaut.security.filters.AuthenticationFetcher;
import io.micronaut.security.token.reader.TokenResolver;
import io.micronaut.security.token.validator.TokenValidator;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.util.Collection;
import java.util.List;

/**
 * Attempts to retrieve a token form the {@link HttpRequest} and if existing validated.
 * It uses a {@link TokenResolver} and the list of {@link TokenValidator} registered in the ApplicationContext.
 *
 * <p>Tokens are validated sequentially, in {@link io.micronaut.security.token.reader.TokenReader} order, and each
 * token is passed to the {@link TokenValidator} beans sequentially, in their {@link io.micronaut.core.order.Ordered}
 * order. The first validator to emit an {@link Authentication} wins: later validators for that token and later tokens
 * are never subscribed. Only the winning token is recorded on the request and only one {@link TokenValidatedEvent}
 * is published.</p>
 *
 * @author Sergio del Amo
 * @author Graeme Rocher
 * @since 1.0
 */
@Requires(classes = HttpRequest.class)
@Requires(beans = HttpHostResolver.class)
@Singleton
public class TokenAuthenticationFetcher implements AuthenticationFetcher<HttpRequest<?>> {

    /**
     * The order of the fetcher.
     */
    public static final Integer ORDER = 0;

    protected final Collection<TokenValidator<HttpRequest<?>>> tokenValidators;
    protected final HttpHostResolver httpHostResolver;
    protected final HttpLocaleResolver httpLocaleResolver;
    protected final ApplicationEventPublisher<TokenValidatedEvent> tokenValidatedEventPublisher;
    private final TokenResolver<HttpRequest<?>> tokenResolver;

    /**
     * @param tokenValidators              The list of {@link TokenValidator} which attempt to validate the request
     * @param tokenResolver                The {@link io.micronaut.security.token.reader.TokenResolver} which returns the first found token in the request.
     * @param tokenValidatedEventPublisher Application event publisher for {@link TokenValidatedEvent}.
     * @param httpHostResolver             The http host resolver
     * @param httpLocaleResolver           The http locale resolver
     * @since 4.7.0
     */
    public TokenAuthenticationFetcher(
        List<TokenValidator<HttpRequest<?>>> tokenValidators,
        TokenResolver<HttpRequest<?>> tokenResolver,
        ApplicationEventPublisher<TokenValidatedEvent> tokenValidatedEventPublisher,
        HttpHostResolver httpHostResolver,
        HttpLocaleResolver httpLocaleResolver
    ) {
        this.tokenValidatedEventPublisher = tokenValidatedEventPublisher;
        this.tokenResolver = tokenResolver;
        this.tokenValidators = tokenValidators;
        this.httpHostResolver = httpHostResolver;
        this.httpLocaleResolver = httpLocaleResolver;
    }

    /**
     * Resolves the tokens present in the request and validates them sequentially.
     *
     * <p>Tokens are tried in the order returned by the {@link TokenResolver} (that is, in
     * {@link io.micronaut.security.token.reader.TokenReader} order) and, for each token, the
     * {@link TokenValidator} beans are tried in their {@link io.micronaut.core.order.Ordered} order.
     * Validation is strictly sequential: a validator is only subscribed once the previous one has
     * completed empty, and a token is only validated once every validator returned empty for the
     * previous token. The first non-empty {@link Authentication} wins; the remaining validators and
     * tokens are never subscribed.</p>
     *
     * <p>Only the winning token is recorded on the request (see {@link io.micronaut.security.filters.SecurityFilter#TOKEN})
     * and only one {@link TokenValidatedEvent}, carrying the winning token, is published.</p>
     *
     * <p>If a validator emits an error, the error is propagated and no further validation is attempted.</p>
     *
     * @param request The request
     * @return A publisher emitting at most one {@link Authentication}
     */
    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {

        List<String> tokens = tokenResolver.resolveTokens(request);
        if (CollectionUtils.isEmpty(tokens)) {
            return Flux.empty();
        }
        return Flux.fromIterable(tokens)
            .concatMap(tokenValue -> Flux.fromIterable(tokenValidators)
                .concatMap(tokenValidator -> tokenValidator.validateToken(tokenValue, request))
                .next()
                .map(authentication -> new ValidatedToken(tokenValue, authentication)))
            .next()
            .doOnNext(validatedToken -> {
                ServerRequestContextSecurityContextSupplier.getSecurityContext(request).withToken(validatedToken.token());
                tokenValidatedEventPublisher.publishEvent(
                    new TokenValidatedEvent(
                        validatedToken.token(),
                        httpHostResolver.resolve(request),
                        httpLocaleResolver.resolveOrDefault(request)
                    )
                );
            })
            .map(ValidatedToken::authentication);
    }

    @Override
    public int getOrder() {
        return ORDER;
    }

    /**
     * A token together with the {@link Authentication} produced by the validator that accepted it.
     *
     * @param token The token value
     * @param authentication The authentication
     */
    private record ValidatedToken(String token, Authentication authentication) {
    }
}
