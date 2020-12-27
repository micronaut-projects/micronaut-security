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
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.endpoint.token.request.TokenEndpointClient;
import io.micronaut.security.oauth2.endpoint.token.request.context.ClientCredentialsTokenRequestContext;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponse;
import io.micronaut.security.oauth2.endpoint.token.response.TokenResponseExpiration;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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
    protected final Map<String, Flowable<TokenResponse>> scopeToPublisherMap = new ConcurrentHashMap<>();

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

        @NonNull Flowable<TokenResponse> publisher = scopeToPublisherMap.getOrDefault(resolvedScope, Flowable.empty());
        return publisher.materialize().firstOrError().flatMapPublisher(tokenNotif -> {
                if (!force && tokenNotif.isOnNext() && !isExpired(tokenNotif.getValue())) {
                    return Flowable.just(tokenNotif.getValue());
                } else if (tokenNotif.isOnError()) {
                    return Flowable.error(tokenNotif.getError());
                }
                ClientCredentialsTokenRequestContext context = createTokenRequestContext(scope);
                Flowable<TokenResponse> tokenResponseCachedObservable = Flowable.fromPublisher(tokenEndpointClient.sendRequest(context)).map(TokenResponseExpiration::new).cast(TokenResponse.class).cache();
                scopeToPublisherMap.put(resolvedScope, tokenResponseCachedObservable);
                return tokenResponseCachedObservable;
        });
    }

    /**
     *
     * @param tokenResponse Token Response
     * @return true if a parameter token response is null or if an expiration time cannot parsed. false if the expiration time is after the current date.
     */
    protected boolean isExpired(@Nullable TokenResponse tokenResponse) {
        if (tokenResponse == null) {
            return true;
        }
        return expirationDate(tokenResponse).map(expDate -> {
            final Date now = new Date();
            long expTime = expDate.getTime();
            expTime = expTime - oauthClientConfiguration.getClientCredentials()
                    .map(ClientCredentialsConfiguration::getAdvancedExpiration)
                    .orElse(OauthClientConfiguration.DEFAULT_ADVANCED_EXPIRATION)
                    .toMillis();
            boolean isExpired = expTime  < now.getTime();
            if (isExpired && LOG.isTraceEnabled()) {
                LOG.trace("token: {} is expired" + tokenResponse.getAccessToken());
            }
            return isExpired;
        }).orElse(true);
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
        if (tokenResponse instanceof TokenResponseExpiration) {
            TokenResponseExpiration tokenResponseExpiration = (TokenResponseExpiration) tokenResponse;
            return Optional.ofNullable(tokenResponseExpiration.getExpiration());
        }
        return Optional.empty();
    }

    /**
     *
     * @param scope The requested scope for the client credentials request
     * @return A client credentials token request context
     */
    protected abstract ClientCredentialsTokenRequestContext createTokenRequestContext(@Nullable String scope);
}
