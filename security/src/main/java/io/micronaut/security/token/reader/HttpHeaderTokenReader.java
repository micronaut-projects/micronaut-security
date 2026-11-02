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
package io.micronaut.security.token.reader;

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads a token from an HTTP request and removes prefix from HTTP Header Value.
 *
 * @author Sergio del Amo
 * @since 1.0
 */
public abstract class HttpHeaderTokenReader implements TokenReader<HttpRequest<?>> {

    private static final Logger LOG = LoggerFactory.getLogger(HttpHeaderTokenReader.class);

    /**
     *
     * @return a Prefix before the token in the header value. E.g. Basic
     */
    protected abstract String getPrefix();

    /**
     *
     * @return an HTTP Header name. e.g. Authorization
     */
    protected abstract String getHeaderName();

    /**
     * Search for a JWT token in a HTTP request.
     * @param request The request to look for the token in
     * @return if the JWT token is found it is returned, empty if not
     */
    @Override
    public Optional<String> findToken(HttpRequest<?> request) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Looking for bearer token in {} header", getHeaderName());
        }
        HttpHeaders headers = request.getHeaders();
        Optional<String> authorizationHeader = headers.findFirst(getHeaderName());
        return authorizationHeader.flatMap(this::extractTokenFromAuthorization);
    }

    /**
     *
     * @param authorization Authorization header value
     * @return If prefix is 'Bearer' for 'Bearer XXX' it returns 'XXX'
     */
    protected Optional<String> extractTokenFromAuthorization(String authorization) {
        final String prefix = getPrefix();
        if (prefix == null || prefix.isEmpty()) {
            return Optional.of(authorization);
        }
        final int prefixLength = prefix.length();
        if (authorization.length() > prefixLength
                && authorization.charAt(prefixLength) == ' '
                && authorization.regionMatches(true, 0, prefix, 0, prefixLength)) {
            return Optional.of(authorization.substring(prefixLength + 1));
        }
        LOG.debug("{} does not start with {}", authorization, prefix);
        return Optional.empty();
    }
}
