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

import io.micronaut.core.annotation.NonNull;
import java.util.List;
import java.util.Optional;

/**
 * Designates a class which caching a Json Web Key Set which may typically be fetched from a remote authorization server.
 * @author Sergio del Amo
 * @since 3.2.0
 */
public interface JwksCache {
    /**
     *
     * @return Whether the cache has been populated.
     */
    boolean isJwksCachePresent();

    /**
     *
     * @return Whether the cache is expired or empty optional if JWKS still not cached
     */
    Optional<Boolean> isJwksCacheExpired();

    /**
     * Clears the JWK Set cache.
     */
    void clearJwksCache();

    /*
     * @return Key IDs for JWK Set or empty optional if JWKS still not cached
     */
    @NonNull
    Optional<List<String>> getJwkstKeyIDs();
}
