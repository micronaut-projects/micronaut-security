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
package io.micronaut.security.token.propagation;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.context.ServerRequestContext;
import io.micronaut.http.filter.ClientFilterChain;
import io.micronaut.http.filter.HttpClientFilter;
import io.micronaut.http.util.OutgoingHttpRequestProcessor;
import org.reactivestreams.Publisher;

import java.util.Optional;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;

/**
 * {@link io.micronaut.http.filter.HttpClientFilter} to enable Token propagation.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@Filter("${" + TokenPropagationConfigurationProperties.PREFIX + ".path:/**}")
@Requires(beans = {TokenPropagator.class, TokenPropagationConfiguration.class})
@Requires(property = TokenPropagationConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE)
public class TokenPropagationHttpClientFilter implements HttpClientFilter {

    protected final TokenPropagationConfiguration tokenPropagationConfiguration;
    protected final OutgoingHttpRequestProcessor outgoingHttpRequestProcessor;
    protected final TokenPropagator tokenPropagator;

    /**
     *
     * @param tokenPropagationConfiguration JWT Propagation configuration
     * @param outgoingHttpRequestProcessor Utility to decide whether to process the request
     * @param tokenPropagator The token propagator
     */
    public TokenPropagationHttpClientFilter(TokenPropagationConfiguration tokenPropagationConfiguration,
                                            OutgoingHttpRequestProcessor outgoingHttpRequestProcessor,
                                            TokenPropagator tokenPropagator) {
        this.tokenPropagationConfiguration = tokenPropagationConfiguration;
        this.outgoingHttpRequestProcessor = outgoingHttpRequestProcessor;
        this.tokenPropagator = tokenPropagator;
    }

    /**
     *
     * @param targetRequest The target request
     * @param chain The filter chain
     * @return The publisher of the response
     */
    @Override
    public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpRequest<?> targetRequest, ClientFilterChain chain) {
        if (!outgoingHttpRequestProcessor.shouldProcessRequest(tokenPropagationConfiguration, targetRequest)) {
            return chain.proceed(targetRequest);
        }

        Optional<HttpRequest<Object>> current = ServerRequestContext.currentRequest();
        if (current.isPresent()) {
            HttpRequest<Object> currentRequest = current.get();
            return doFilter(targetRequest, chain, currentRequest);
        } else {
            return chain.proceed(targetRequest);
        }
    }

    /**
     *
     * @param targetRequest The target request of this HttpClientFilter
     * @param chain The filter chain
     * @param currentRequest The original request which triggered during its execution the invocation of this HttpClientFilter
     * @return The publisher of the response
     */
    public Publisher<? extends HttpResponse<?>> doFilter(MutableHttpRequest<?> targetRequest, ClientFilterChain chain, HttpRequest<Object> currentRequest) {
        Optional<Object> token = currentRequest.getAttribute(TOKEN);
        if (token.isPresent()) {
            Object obj = token.get();

            if (obj instanceof String) {
                String tokenValue = (String) obj;
                if (!hasExistingToken(targetRequest)) {
                    tokenPropagator.writeToken(targetRequest, tokenValue);
                }
                return chain.proceed(targetRequest);
            }
        }
        return chain.proceed(targetRequest);
    }

    private boolean hasExistingToken(MutableHttpRequest<?> targetRequest) {
        return tokenPropagator.findToken(targetRequest).isPresent();
    }
}
