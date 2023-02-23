/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.jwt.signature.jwks;

import io.micronaut.context.annotation.DefaultImplementation;
import io.micronaut.core.annotation.Blocking;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.annotation.Nullable;
import java.util.Optional;

/**
 * Fetch a Json Web Key Set by a given url.
 * @author Sergio del Amo
 * @since 3.9.0
 * @param <T> Json Web Key Set type
 */
@DefaultImplementation(DefaultJwkSetFetcher.class)
public interface JwkSetFetcher<T> {
    /**
     *
     * @param url The Jwks uri
     * @return The Json Web Key Set representation or an empty optional if it could not be loaded
     */
    @NonNull
    @Blocking
    Optional<T> fetch(@Nullable String url);

    /**
     * @param url The Jwks uri
     * Clears cache
     */
    void clearCache(String url);
}
