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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import io.micronaut.core.annotation.Internal;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

/**
 * Binds configuration for the Argon2id password encoder.
 *
 * <p>The configuration is bound and validated when the application context starts, so an invalid
 * configuration prevents the application from starting.</p>
 *
 * @since 5.5.0
 */
@ConfigurationProperties(Argon2PasswordEncoderConfigurationProperties.PREFIX)
@Context
@ValidArgon2Costs
@Internal
public final class Argon2PasswordEncoderConfigurationProperties implements Argon2PasswordEncoderConfiguration {
    /** Configuration prefix for the Argon2id password encoder. */
    public static final String PREFIX = "micronaut.security.password.argon2";
    /** Default memory cost, in kibibytes. */
    public static final int DEFAULT_MEMORY = 19456;
    /** Default number of iterations. */
    public static final int DEFAULT_ITERATIONS = 2;
    /** Default degree of parallelism. */
    public static final int DEFAULT_PARALLELISM = 1;
    /** Default salt length, in bytes. */
    public static final int DEFAULT_SALT_LENGTH = 16;
    /** Default hash length, in bytes. */
    public static final int DEFAULT_HASH_LENGTH = 32;
    /** Default highest memory cost, in kibibytes, accepted when verifying an encoded password. */
    public static final int DEFAULT_MAX_MEMORY = 262144;
    /** Default highest number of iterations accepted when verifying an encoded password. */
    public static final int DEFAULT_MAX_ITERATIONS = 10;

    private int memory = DEFAULT_MEMORY;

    @Min(1)
    private int iterations = DEFAULT_ITERATIONS;

    @Min(1)
    @Max(Argon2PhcString.MAX_PARALLELISM)
    private int parallelism = DEFAULT_PARALLELISM;

    @Min(Argon2PhcString.MIN_SALT_LENGTH)
    @Max(Argon2PhcString.MAX_SALT_LENGTH)
    private int saltLength = DEFAULT_SALT_LENGTH;

    @Min(Argon2PhcString.MIN_HASH_LENGTH)
    @Max(Argon2PhcString.MAX_HASH_LENGTH)
    private int hashLength = DEFAULT_HASH_LENGTH;

    private int maxMemory = DEFAULT_MAX_MEMORY;
    private int maxIterations = DEFAULT_MAX_ITERATIONS;

    @Override
    public int getMemory() {
        return memory;
    }

    /**
     * Sets the memory cost, in kibibytes, used to encode passwords. It must be at least eight times
     * the parallelism and at most the maximum memory. Default value ({@value #DEFAULT_MEMORY}).
     *
     * @param memory the memory cost, in kibibytes
     */
    public void setMemory(int memory) {
        this.memory = memory;
    }

    @Override
    public int getIterations() {
        return iterations;
    }

    /**
     * Sets the number of iterations used to encode passwords. It must be at least 1 and at most
     * the maximum iterations. Default value ({@value #DEFAULT_ITERATIONS}).
     *
     * @param iterations the number of iterations
     */
    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    @Override
    public int getParallelism() {
        return parallelism;
    }

    /**
     * Sets the degree of parallelism used to encode passwords. It must be between 1 and 255.
     * Default value ({@value #DEFAULT_PARALLELISM}).
     *
     * @param parallelism the degree of parallelism
     */
    public void setParallelism(int parallelism) {
        this.parallelism = parallelism;
    }

    @Override
    public int getSaltLength() {
        return saltLength;
    }

    /**
     * Sets the length, in bytes, of the salt generated for each encoded password. It must be
     * between 8 and 48. Default value ({@value #DEFAULT_SALT_LENGTH}).
     *
     * @param saltLength the salt length, in bytes
     */
    public void setSaltLength(int saltLength) {
        this.saltLength = saltLength;
    }

    @Override
    public int getHashLength() {
        return hashLength;
    }

    /**
     * Sets the length, in bytes, of the hash generated for each encoded password. It must be
     * between 12 and 64. Default value ({@value #DEFAULT_HASH_LENGTH}).
     *
     * @param hashLength the hash length, in bytes
     */
    public void setHashLength(int hashLength) {
        this.hashLength = hashLength;
    }

    @Override
    public int getMaxMemory() {
        return maxMemory;
    }

    /**
     * Sets the highest memory cost, in kibibytes, accepted when verifying an encoded password. An
     * encoded password that declares a higher memory cost does not match any password.
     * Default value ({@value #DEFAULT_MAX_MEMORY}).
     *
     * @param maxMemory the highest memory cost, in kibibytes
     */
    public void setMaxMemory(int maxMemory) {
        this.maxMemory = maxMemory;
    }

    @Override
    public int getMaxIterations() {
        return maxIterations;
    }

    /**
     * Sets the highest number of iterations accepted when verifying an encoded password. An
     * encoded password that declares more iterations does not match any password.
     * Default value ({@value #DEFAULT_MAX_ITERATIONS}).
     *
     * @param maxIterations the highest number of iterations
     */
    public void setMaxIterations(int maxIterations) {
        this.maxIterations = maxIterations;
    }
}
