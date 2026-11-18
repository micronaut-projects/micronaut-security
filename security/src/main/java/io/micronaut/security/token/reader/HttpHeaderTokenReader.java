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

import io.micronaut.core.util.StringUtils;
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
     * Search for a token in a HTTP request.
     * @param request The request to look for the token in
     * @return if the token is found it is returned, empty if not
     */
    @Override
    public Optional<String> findToken(HttpRequest<?> request) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Looking for token in {} header", getHeaderName());
        }
        HttpHeaders headers = request.getHeaders();
        Optional<String> authorizationHeader = headers.findFirst(getHeaderName());
        return authorizationHeader.flatMap(this::extractTokenFromAuthorization);
    }

    /**
     * Removes the prefix returned by {@link #getPrefix()} and the single space after it from the header value.
     * The prefix is compared ignoring case. Only one space is removed, so the token may be empty or start with a space.
     * If the prefix is {@code null} or empty, the whole header value is the token.
     *
     * @param authorization Authorization header value
     * @return If prefix is 'Bearer' for 'Bearer XXX' it returns 'XXX'. Empty if the value does not start with the prefix and a space.
     */
    protected Optional<String> extractTokenFromAuthorization(String authorization) {
        final String prefix = getPrefix();
        if (StringUtils.isEmpty(prefix)) {
            return Optional.of(authorization);
        }
        final int prefixLength = prefix.length();
        if (authorization.length() > prefixLength
                && authorization.charAt(prefixLength) == ' '
                && startsWithIgnoreCase(authorization, prefix)) {
            return Optional.of(authorization.substring(prefixLength + 1));
        }
        LOG.debug("{} header does not start with {}", getHeaderName(), prefix);
        return Optional.empty();
    }

    /**
     * Compares characters by their lower-case form only. {@link String#regionMatches(boolean, int, String, int, int)}
     * also folds through upper case, which would accept look-alikes such as {@code "Baſıc"} for {@code "Basic"}.
     *
     * @param value  The value to test. It must be at least as long as the prefix.
     * @param prefix The expected prefix
     * @return Whether the value starts with the prefix, ignoring case
     */
    private static boolean startsWithIgnoreCase(String value, String prefix) {
        for (int i = 0; i < prefix.length(); i++) {
            char expected = prefix.charAt(i);
            char actual = value.charAt(i);
            if (expected != actual && Character.toLowerCase(expected) != Character.toLowerCase(actual)) {
                return false;
            }
        }
        return true;
    }
}
