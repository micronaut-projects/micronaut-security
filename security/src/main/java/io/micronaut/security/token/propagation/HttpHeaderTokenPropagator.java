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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import jakarta.inject.Singleton;
import java.util.Optional;

/**
 * Propagates a token based off of a header.
 *
 * @author James Kleeh
 * @since 1.4.0
 */
@Requires(property = HttpHeaderTokenPropagatorConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(classes = { HttpRequest.class })
@Singleton
public class HttpHeaderTokenPropagator implements TokenPropagator {

    protected final HttpHeaderTokenPropagatorConfiguration configuration;

    /**
     * @param configuration The token propagator configuration
     */
    public HttpHeaderTokenPropagator(HttpHeaderTokenPropagatorConfiguration configuration) {
        this.configuration = configuration;
    }

    /**
     * Writes the token to the request.
     * @param request The {@link MutableHttpRequest} instance
     * @param token A token ( e.g. JWT token, basic auth token...)
     */
    @Override
    public void writeToken(MutableHttpRequest<?> request, String token) {
        request.getHeaders().set(configuration.getHeaderName(), headerValue(token));
    }

    /**
     * Search for a JWT token in a HTTP request.
     * @param request The request to look for the token in
     * @return if the JWT token is found it is returned, empty if not
     */
    @Override
    public Optional<String> findToken(HttpRequest<?> request) {
        HttpHeaders headers = request.getHeaders();
        Optional<String> authorizationHeader = headers.findFirst(configuration.getHeaderName());
        return authorizationHeader.flatMap(this::extractTokenFromAuthorization);
    }

    /**
     * @param token the token being written
     * @return the value which will be written to an HTTP Header
     */
    protected String headerValue(String token) {
        String prefix = effectivePrefix();
        if (prefix == null) {
            return token;
        }
        return prefix + " " + token;
    }

    /**
     * Extracts the token from the header value. Prefix matching is case-insensitive and requires a
     * single space separator between the prefix and the token. An empty or blank prefix is treated
     * as no prefix.
     * @param authorization Authorization header value
     * @return If prefix is 'Bearer' for 'Bearer XXX' it returns 'XXX'
     */
    protected Optional<String> extractTokenFromAuthorization(String authorization) {
        final String prefix = effectivePrefix();
        if (prefix == null) {
            return Optional.of(authorization);
        }
        final int prefixLength = prefix.length();
        if (authorization.length() > prefixLength
                && authorization.regionMatches(true, 0, prefix, 0, prefixLength)
                && authorization.charAt(prefixLength) == ' ') {
            return Optional.of(authorization.substring(prefixLength + 1));
        }
        return Optional.empty();
    }

    /**
     * @return the configured prefix without surrounding whitespace, or {@code null} if no prefix is configured or it is blank
     */
    @Nullable
    private String effectivePrefix() {
        String prefix = configuration.getPrefix();
        if (prefix == null) {
            return null;
        }
        String trimmed = prefix.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     *
     * @return The HttpHeaderTokenPropagator Configuration
     */
    public HttpHeaderTokenPropagatorConfiguration getConfiguration() {
        return configuration;
    }
}
