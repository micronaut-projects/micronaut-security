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

/**
 * Configuration of the Argon2id {@link io.micronaut.security.password.PasswordEncoder}.
 *
 * <p>The memory, iterations, parallelism, salt length and hash length apply to newly encoded
 * passwords. An encoded password is always verified with the parameters it was created with, as
 * long as they do not exceed the maximum memory and maximum iterations.</p>
 *
 * @since 5.5.0
 */
@Internal
public interface Argon2PasswordEncoderConfiguration {

    /**
     * @return the memory cost, in kibibytes, used to encode passwords
     */
    int getMemory();

    /**
     * @return the number of iterations used to encode passwords
     */
    int getIterations();

    /**
     * @return the degree of parallelism used to encode passwords
     */
    int getParallelism();

    /**
     * @return the length of the generated salt, in bytes
     */
    int getSaltLength();

    /**
     * @return the length of the generated hash, in bytes
     */
    int getHashLength();

    /**
     * @return the highest memory cost, in kibibytes, accepted when verifying an encoded password
     */
    int getMaxMemory();

    /**
     * @return the highest number of iterations accepted when verifying an encoded password
     */
    int getMaxIterations();
}
