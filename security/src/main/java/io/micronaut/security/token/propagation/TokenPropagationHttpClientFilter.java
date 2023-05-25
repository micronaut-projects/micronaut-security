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
package io.micronaut.security.token.propagation;

import static io.micronaut.security.filters.SecurityFilter.TOKEN;

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.annotation.ClientFilter;
import io.micronaut.http.annotation.RequestFilter;
import io.micronaut.http.context.ServerHttpRequestContext;
import io.micronaut.http.util.OutgoingHttpRequestProcessor;

import java.util.Optional;

/**
 * {@link io.micronaut.http.filter.HttpClientFilter} to enable Token propagation.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
@ClientFilter("${" + TokenPropagationConfigurationProperties.PREFIX + ".path:/**}")
@Requires(classes = ClientFilter.class)
@Requires(beans = {TokenPropagator.class, TokenPropagationConfiguration.class})
@Requires(property = TokenPropagationConfigurationProperties.PREFIX + ".enabled", value = StringUtils.TRUE)
public class TokenPropagationHttpClientFilter {

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
     * @param targetRequest The HTTP request
     */
    @RequestFilter
    public void doFilter(MutableHttpRequest<?> targetRequest) {
        if (!hasExistingToken(targetRequest) && outgoingHttpRequestProcessor.shouldProcessRequest(tokenPropagationConfiguration, targetRequest)) {
            Optional<HttpRequest<Object>> currentRequestOptional = ServerHttpRequestContext.find();
            if (currentRequestOptional.isPresent()) {
                HttpRequest<Object> currentRequest = currentRequestOptional.get();
                Optional<String> tokenOptional = currentRequest.getAttribute(TOKEN, String.class);
                if (tokenOptional.isPresent()) {
                    String token = tokenOptional.get();
                    tokenPropagator.writeToken(targetRequest, token);
                }
            }
        }
    }

    private boolean hasExistingToken(MutableHttpRequest<?> targetRequest) {
        return tokenPropagator.findToken(targetRequest).isPresent();
    }
}
