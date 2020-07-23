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
package io.micronaut.security.token.reader;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.http.HttpRequest;

import java.util.Optional;

/**
 * Returns the token from the provided request.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 */
@DefaultImplementation(DefaultTokenResolver.class)
@FunctionalInterface
public interface TokenResolver {

    /**
     * Resolves the token from the provided request.
     *
     * @param request The HTTP request.
     * @return The token in the supplied request. Empty if no token was found.
     */
    Optional<String> resolveToken(HttpRequest<?> request);
}
