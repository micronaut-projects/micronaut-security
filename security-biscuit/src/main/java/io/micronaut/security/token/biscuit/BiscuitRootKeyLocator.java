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
package io.micronaut.security.token.biscuit;

import org.biscuitsec.biscuit.crypto.PublicKey;
import org.jspecify.annotations.Nullable;

import java.util.Optional;

/**
 * Locates Biscuit root public keys.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public interface BiscuitRootKeyLocator {

    /**
     * Finds a Biscuit root public key.
     * @param keyId The optional Biscuit root key identifier
     * @return The root public key, if known
     */
    Optional<PublicKey> findRootKey(@Nullable Integer keyId);
}
