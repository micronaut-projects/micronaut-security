/*
 * Copyright 2017-2026 original authors
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

import io.micronaut.core.annotation.Internal;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Reactor context object used to coordinate JWKS retrieval logging during reactive JWT signature validation.
 *
 * @since 4.16.0
 */
@Internal
public final class JwksClientReactorContext {
    private final AtomicBoolean tokenVerified = new AtomicBoolean(false);
    private final AtomicBoolean refreshOnUnknownKeyId = new AtomicBoolean(false);
    private final AtomicBoolean keyIdUnknown = new AtomicBoolean(false);

    /**
     * @return Whether the token has already been verified by any configured signature.
     */
    public boolean isTokenVerified() {
        return tokenVerified.get();
    }

    /**
     * Mark the token as verified.
     */
    public void markTokenVerified() {
        tokenVerified.set(true);
    }

    /**
     * @return Whether a JWKS signature configuration may clear its cache and fetch the JWKS again when the token key ID is not present in the cached JWKS.
     * @since 5.5.3
     */
    public boolean isRefreshOnUnknownKeyId() {
        return refreshOnUnknownKeyId.get();
    }

    /**
     * Allow JWKS signature configurations to refresh the cached JWKS when the token key ID is not present in the cached JWKS.
     * @since 5.5.3
     */
    public void allowRefreshOnUnknownKeyId() {
        refreshOnUnknownKeyId.set(true);
    }

    /**
     * @return Whether a JWKS signature configuration reported that the token key ID is not present in its cached JWKS.
     * @since 5.5.3
     */
    public boolean isKeyIdUnknown() {
        return keyIdUnknown.get();
    }

    /**
     * Reports that the token key ID is not present in the cached JWKS of a signature configuration, so a refresh of that JWKS may verify the token.
     * @since 5.5.3
     */
    public void markKeyIdUnknown() {
        keyIdUnknown.set(true);
    }
}
