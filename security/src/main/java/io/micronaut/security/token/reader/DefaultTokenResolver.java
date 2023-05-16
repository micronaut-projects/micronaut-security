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

import io.micronaut.http.HttpRequest;
import jakarta.inject.Singleton;
import java.util.Collection;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link io.micronaut.security.token.reader.TokenResolver}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Singleton
public class DefaultTokenResolver implements TokenResolver<HttpRequest<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenResolver.class);
    private final Collection<TokenReader<HttpRequest<?>>> tokenReaders;

    /**
     * Instantiates a {@link io.micronaut.security.token.reader.DefaultTokenResolver} with a list of available {@link io.micronaut.security.token.reader.TokenReader}.
     * @param tokenReaders Collection of available {@link io.micronaut.security.token.reader.TokenReader} beans.
     */
    public DefaultTokenResolver(Collection<TokenReader<HttpRequest<?>>> tokenReaders) {
        this.tokenReaders = tokenReaders;
    }

    /**
     * Returns the first token found by the supplied token readers.
     *
     * @param request The current HTTP request.
     * @return the first found token in the supplied request.
     */
    @Override
    public Optional<String> resolveToken(HttpRequest<?> request) {
        Optional<String> token = this.tokenReaders
            .stream()
            .map(reader -> reader.findToken(request))
            .filter(Optional::isPresent)
            .findFirst()
            .orElse(Optional.empty());
        if (LOG.isDebugEnabled()) {
            String method = request.getMethod().toString();
            String path = request.getPath();
            if (token.isPresent()) {
                LOG.debug("Token {} found in request {} {}", token.get(), method, path);
            } else {
                LOG.debug("Request {}, {}, no token found.", method, path);
            }
        }
        return token;
    }
}
