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

import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.CollectionUtils;
import io.micronaut.http.HttpRequest;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link io.micronaut.security.token.reader.TokenResolver}.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@Requires(classes = HttpRequest.class)
@Singleton
public class DefaultTokenResolver implements TokenResolver<HttpRequest<?>> {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultTokenResolver.class);
    private final List<TokenReader<HttpRequest<?>>> tokenReaders;

    /**
     * Instantiates a {@link io.micronaut.security.token.reader.DefaultTokenResolver} with a list of available {@link io.micronaut.security.token.reader.TokenReader}.
     * @param tokenReaders Collection of available {@link io.micronaut.security.token.reader.TokenReader} beans.
     * @deprecated Use {@link DefaultTokenResolver(List)} instead.
     */
    @Deprecated(forRemoval = true, since = "4.4.0")
    public DefaultTokenResolver(Collection<TokenReader<HttpRequest<?>>> tokenReaders) {
        this(new ArrayList<>(tokenReaders));
    }

    /**
     * Instantiates a {@link io.micronaut.security.token.reader.DefaultTokenResolver} with a list of available {@link io.micronaut.security.token.reader.TokenReader}.
     * @param tokenReaders Collection of available {@link io.micronaut.security.token.reader.TokenReader} beans.
     * @since 4.4.0
     */
    @Inject
    public DefaultTokenResolver(List<TokenReader<HttpRequest<?>>> tokenReaders) {
        this.tokenReaders = tokenReaders;
    }

    @Override
    @NonNull
    public List<String> resolveTokens(@NonNull HttpRequest<?> request) {
        List<String> tokens = this.tokenReaders
                .stream()
                .map(reader -> reader.findToken(request))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .peek(token -> {
                    if (LOG.isDebugEnabled()) {
                        String method = request.getMethod().toString();
                        String path = request.getPath();
                        LOG.debug("Token {} found in request {} {}", token, method, path);
                    }
                })
                .toList();
        if (LOG.isDebugEnabled() && CollectionUtils.isEmpty(tokens)) {
            String method = request.getMethod().toString();
            String path = request.getPath();
            LOG.debug("Request {}, {}, no token found.", method, path);
        }
        return tokens;
    }

    /**
     * Returns the first token found by the supplied token readers.
     *
     * @param request The current HTTP request.
     * @return the first found token in the supplied request.
     */
    @Override
    public Optional<String> resolveToken(HttpRequest<?> request) {
        return resolveTokens(request).stream().findFirst();
    }
}
