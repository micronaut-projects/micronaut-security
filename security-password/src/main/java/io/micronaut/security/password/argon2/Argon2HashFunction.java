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
package io.micronaut.security.password.argon2;

import io.micronaut.core.annotation.Internal;
import io.micronaut.core.naming.Named;

/**
 * Computes Argon2id hashes for an {@link Argon2PasswordEncoder}.
 * Implementations must be safe for concurrent use and return the requested number of bytes.
 *
 * @since 5.5.0
 */
@Internal
public interface Argon2HashFunction extends Named {

    /**
     * Hashes a password using the requested parameters.
     *
     * @param rawPassword the password
     * @param salt the salt
     * @param memory memory cost in kibibytes
     * @param iterations time cost
     * @param parallelism number of lanes
     * @param hashLength number of output bytes
     * @return the Argon2id hash
     */
    byte[] hash(String rawPassword, byte[] salt, int memory, int iterations, int parallelism, int hashLength);
}
