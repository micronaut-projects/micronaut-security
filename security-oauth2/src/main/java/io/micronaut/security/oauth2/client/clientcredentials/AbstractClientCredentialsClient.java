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
package io.micronaut.security.oauth2.client.clientcredentials;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Abstract class to create a Client for client credentials grant.
 *
 * @author Sergio del Amo
 * @since 2.2.0
 */
@Internal
public abstract class AbstractClientCredentialsClient implements ClientCredentialsClient {
    private static final Logger LOG = LoggerFactory.getLogger(AbstractClientCredentialsClient.class);
    private static final String NOSCOPE = "NOSCOPE";
    protected final TokenEndpointClient tokenEndpointClient;
    protected final OauthClientConfiguration oauthClientConfiguration;
    protected final Map<String, Publisher<TokenResponse>> scopeToPublisherMap = new ConcurrentHashMap<>();

    /**
     * @param tokenEndpointClient The token endpoint client
     * @param oauthClientConfiguration The client configuration
     */
    public AbstractClientCredentialsClient(@NonNull OauthClientConfiguration oauthClientConfiguration,
                                           @NonNull TokenEndpointClient tokenEndpointClient) {
        this.oauthClientConfiguration = oauthClientConfiguration;
        this.tokenEndpointClient = tokenEndpointClient;
    }

    /**
     *
     * @return the bean's name;
     */
    public String getName() {
        return oauthClientConfiguration.getName();
    }

    @NonNull
    @Override
    public Publisher<TokenResponse> requestToken(@Nullable String scope) {
        return requestToken(scope, false);
    }

    @Override
    @NonNull
    public Publisher<TokenResponse> requestToken(@Nullable String scope, boolean force) {
        String resolvedScope = scope != null ? scope : NOSCOPE;
        return Flux.from(scopeToPublisherMap.computeIfAbsent(resolvedScope, k -> cachedTokenResponseForScope(scope)))
                .materialize()
                .next()
                .flatMap((Function<Signal<TokenResponse>, Mono<TokenResponse>>) tokenNotif -> {
                    if (!force && tokenNotif.isOnNext() && !isExpired(tokenNotif.get())) {
                        TokenResponse tokenResponse = tokenNotif.get();
                        return tokenResponse != null ? Mono.just(tokenResponse) : Mono.empty();
                    } else if (tokenNotif.isOnError()) {
                        return tokenNotif.getThrowable() != null ? Mono.error(tokenNotif.getThrowable()) : Mono.error(Throwable::new);
                    }
                    return Mono.from(scopeToPublisherMap.computeIfPresent(resolvedScope, (s, tokenResponse) -> cachedTokenResponseForScope(scope)));
                });
    }

    @NonNull
    private Publisher<TokenResponse> cachedTokenResponseForScope(String scope) {
        return Flux.from(tokenEndpointClient.sendRequest(createTokenRequestContext(scope))).cache();
    }

    /**
     *
     * @param tokenResponse Token Response
     * @return true if any A) parameter token response is null B) if an expiration time cannot parsed C) (expiration date - {@link ClientCredentialsConfiguration#getAdvancedExpiration()}) before current date.
     */
    protected boolean isExpired(@Nullable TokenResponse tokenResponse) {
        if (tokenResponse == null) {
            return true;
        }
        return expirationDate(tokenResponse).map(expDate -> {
            boolean isExpired = isExpired(expDate);
            if (isExpired && LOG.isTraceEnabled()) {
                LOG.trace("token: {} is expired" + tokenResponse.getAccessToken());
            }
            return isExpired;
        }).orElse(true);
    }

    /**
     *
     * @param expirationDate Expiration
     * @return true if the (expiration date - {@link ClientCredentialsConfiguration#getAdvancedExpiration()}) before current date.
     */
    protected boolean isExpired(@NonNull Date expirationDate) {
        return (expirationDate.getTime() - oauthClientConfiguration.getClientCredentials()
                .map(ClientCredentialsConfiguration::getAdvancedExpiration)
                .orElse(OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION)
                .toMillis()) < new Date().getTime();
    }

    /**
     *
     * @param tokenResponse Token Response
     * @return The expiration date from the exp claim in the access token is a JWT or the expiration date calculated from the expiresIn
     */
    protected Optional<Date> expirationDate(@NonNull TokenResponse tokenResponse) {
        try {
            JWT jwt = JWTParser.parse(tokenResponse.getAccessToken());
            return Optional.ofNullable(jwt.getJWTClaimsSet().getExpirationTime());
        } catch (ParseException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("cannot parse access token {} to JWT", tokenResponse.getAccessToken());
            }
        }
        return tokenResponse.getExpiresInDate();
    }

    /**
     *
     * @param scope The requested scope for the client credentials request
     * @return A client credentials token request context
     */
    protected abstract ClientCredentialsTokenRequestContext createTokenRequestContext(@Nullable String scope);
}
