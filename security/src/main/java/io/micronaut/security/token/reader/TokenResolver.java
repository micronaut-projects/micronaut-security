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

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.NonNull;

import java.util.List;

/**
 * Returns the token from the provided request.
 *
 * @author Sergio del Amo
 * @since 1.1.0
 * @param <T> request
 */
@DefaultImplementation(DefaultTokenResolver.class)
@FunctionalInterface
public interface TokenResolver<T> {
    /**
     * Returns tokens found by the supplied token readers.
     *
     * @param request The current HTTP request.
     * @return the tokens found in the supplied request.
     * @since 4.4.0
     */
    @NonNull
    List<String> resolveTokens(@NonNull T request);
}
