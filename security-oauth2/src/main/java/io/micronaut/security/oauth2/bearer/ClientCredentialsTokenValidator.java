/*
 * Copyright 2017-2019 original authors
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

package io.micronaut.security.oauth2.bearer;

import io.micronaut.cache.CacheManager;
import io.micronaut.cache.SyncCache;
import io.micronaut.context.BeanContext;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.type.Argument;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.client.RxHttpClient;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.oauth2.configuration.OauthClientConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.EndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.IntrospectionEndpointConfiguration;
import io.micronaut.security.oauth2.configuration.endpoints.SecureEndpointConfiguration;
import io.micronaut.security.oauth2.endpoint.AuthenticationMethod;
import io.micronaut.security.token.validator.TokenValidator;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;

/**
 * Token validator that uses OAuth 2.0 Token Introspection endpoint to validate token and authorize access.
 *
 * @author svishnyakoff
 * @see <a href="https://tools.ietf.org/html/rfc7662">rfc7662</a>
 */
@Internal
public class ClientCredentialsTokenValidator implements TokenValidator {

    static final String OAUTH_TOKEN_AUTHORIZATION_CONFIG = "micronaut.security.token.oauth2.bearer";

    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsTokenValidator.class);

    private final OauthClientConfiguration clientConfiguration;
    private final RxHttpClient oauthIntrospectionClient;
    private final List<TokenIntrospectionHandler> introspectionHandlers;
    private final String introspectionUrl;
    private final AuthenticationMethod authMethod;
    private final IntrospectionEndpointConfiguration introspectionConfiguration;
    private final SyncCache<Object> cache;

    /**
     * @param introspectedTokenValidators list of handlers that will proceed token introspection metadata.
     * @param clientConfiguration         oauth client configuration with "client credentials" grant
     * @param cacheManager                cache manager
     * @param beanContext                 bean context
     */
    public ClientCredentialsTokenValidator(List<TokenIntrospectionHandler> introspectedTokenValidators,
                                           OauthClientConfiguration clientConfiguration,
                                           CacheManager<Object> cacheManager,
                                           BeanContext beanContext) {

        this(introspectedTokenValidators,
             clientConfiguration,
             cacheManager,
             beanContext.createBean(RxHttpClient.class, clientConfiguration.getIntrospection().get().getUrl()
                     .orElseThrow(() -> new IllegalArgumentException("Introspection url is missing"))));
    }

    /**
     * @param oauthClientConfiguration    oauth client configuration with "client credentials" grant
     * @param introspectedTokenValidators list of handlers that will proceed token introspection metadata.
     * @param cacheManager                cache manager
     * @param httpClient                  http client used to call introspection endpoint
     */
    public ClientCredentialsTokenValidator(List<TokenIntrospectionHandler> introspectedTokenValidators,
                                           OauthClientConfiguration oauthClientConfiguration,
                                           CacheManager<Object> cacheManager,
                                           RxHttpClient httpClient) {
        this.oauthIntrospectionClient = httpClient;
        this.introspectionHandlers = introspectedTokenValidators;
        this.clientConfiguration = oauthClientConfiguration;
        this.introspectionUrl = clientConfiguration.getIntrospection().flatMap(EndpointConfiguration::getUrl).get();
        this.authMethod = clientConfiguration.getIntrospection().flatMap(SecureEndpointConfiguration::getAuthMethod).get();
        this.introspectionConfiguration = clientConfiguration.getIntrospection().get();

        if (cacheManager.getCacheNames().contains(this.clientConfiguration.getName())) {
            this.cache = cacheManager.getCache(this.clientConfiguration.getName());
        } else {
            this.cache = null;
        }

    }

    @Override
    public Publisher<Authentication> validateToken(String token) {

        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("Bearer token cannot be null or empty");
        }

        if (cache != null) {
            Optional<IntrospectedToken> cachedTokenIntrospection = cache.get(token, IntrospectedToken.class);

            if (cachedTokenIntrospection.isPresent()) {
                IntrospectedToken tokenIntrospection = cachedTokenIntrospection.get();

                long currentTimestamp = TimeUnit.SECONDS.convert(System.currentTimeMillis(), TimeUnit.MILLISECONDS);

                if (currentTimestamp < tokenIntrospection.getTokenExpirationTime()) {
                    return Flowable.just(tokenIntrospection);
                }

                cache.invalidate(token);
            }
        }

        MutableHttpRequest<String> request = HttpRequest
                .POST(introspectionUrl, tokenIntrospectionRequestBody(token))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        secureRequest(request);

        return oauthIntrospectionClient.exchange(request, Argument.of(Map.class, String.class, Object.class))
                .flatMap(response -> {
                    if (response.status() == HttpStatus.UNAUTHORIZED) {
                        LOG.error("Authorization service requires valid credentials to call introspection endpoint");
                        return Flowable.empty();
                    } else if (response.status() != HttpStatus.OK) {
                        LOG.error("Request to introspection endpoint failed with: {}", response.getStatus().getCode());
                        return Flowable.empty();
                    }

                    try {
                        Map<String, Object> introspectionMetadata = (Map<String, Object>) response.body();

                        if (introspectionMetadata == null) {
                            LOG.error("Introspection endpoint return empty body. Valid json is expected.");
                            return Flowable.empty();
                        }

                        Optional<IntrospectedToken> activeToken = introspectionHandlers.stream()
                                .map(validator -> validator.handle(introspectionMetadata))
                                .filter(IntrospectedToken::isActive)
                                .findFirst();

                        if (cache != null) {
                            activeToken.ifPresent(authenticatedToken -> cache.put(token, authenticatedToken));
                        }

                        return activeToken.map(Flowable::just).orElse(Flowable.empty());
                    } catch (Exception e) {
                        LOG.error("Token introspection url must return valid json response");
                        return Flowable.empty();
                    }
                });
    }

    private <T> MutableHttpRequest<T> secureRequest(MutableHttpRequest<T> request) {
        if (authMethod == AuthenticationMethod.CLIENT_SECRET_BASIC) {
            LOG.debug("Adding basic authorization to introspection request");
            request.basicAuth(clientConfiguration.getClientId(), clientConfiguration.getClientSecret());
        }

        return request;
    }

    private String tokenIntrospectionRequestBody(String token) {
        String tokenParam = introspectionConfiguration.getTokenParam() + "=" + token;
        StringJoiner joiner = new StringJoiner("&");
        joiner.add(tokenParam);

        introspectionConfiguration.getTokenHintsParameters().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .forEach(joiner::add);

        return joiner.toString();
    }
}
