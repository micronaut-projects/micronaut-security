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
package io.micronaut.security.token.jwt.signature.ec;

import io.micronaut.core.annotation.NonNull;

import java.security.interfaces.ECPrivateKey;
import java.util.Optional;

/**
 * Elliptic curve signature generation configuration.
 * @author Sergio del Amo
 * @since 1.0
 */
public interface ECSignatureGeneratorConfiguration extends ECSignatureConfiguration {

    /**
     *
     * @return The EC Private Key
     */
    ECPrivateKey getPrivateKey();

    /**
     *
     * @return The Key ID
     * @since 3.9.0
     */
    @NonNull
    default Optional<String> getKid() {
        return Optional.empty();
    }
}
