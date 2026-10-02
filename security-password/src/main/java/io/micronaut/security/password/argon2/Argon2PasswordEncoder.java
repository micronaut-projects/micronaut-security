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

import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Shared Argon2id password policy and PHC string handling for hash implementations.
 *
 * <p>Subclasses provide the Argon2id hash operation. Each invocation must be safe for concurrent
 * use and return exactly {@code hashLength} bytes.</p>
 */
@Requires(bean = Argon2HashFunction.class)
@Singleton
@Internal
final class Argon2PasswordEncoder implements PasswordEncoder {
    private static final Logger LOG = LoggerFactory.getLogger(Argon2PasswordEncoder.class);
    private static final int MEMORY_PER_LANE = 8;

    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final int saltLength;
    private final int hashLength;
    private final int maxMemory;
    private final int maxIterations;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Argon2HashFunction argon2HashFunction;

    /**
     * Validates the configuration used for newly encoded passwords.
     *
     * @param configuration the Argon2id configuration
     * @param argon2HashFunction the Argon2 Hashfunction
     */
    Argon2PasswordEncoder(Argon2PasswordEncoderConfiguration configuration, Argon2HashFunction argon2HashFunction) {
        this.parallelism = requireRange("parallelism", configuration.getParallelism(), 1, Argon2PhcString.MAX_PARALLELISM);
        this.maxMemory = configuration.getMaxMemory();
        this.maxIterations = configuration.getMaxIterations();
        this.memory = requireRange("memory", configuration.getMemory(), MEMORY_PER_LANE * parallelism, maxMemory);
        this.iterations = requireRange("iterations", configuration.getIterations(), 1, maxIterations);
        this.saltLength = requireRange("salt-length", configuration.getSaltLength(), Argon2PhcString.MIN_SALT_LENGTH, Argon2PhcString.MAX_SALT_LENGTH);
        this.hashLength = requireRange("hash-length", configuration.getHashLength(), Argon2PhcString.MIN_HASH_LENGTH, Argon2PhcString.MAX_HASH_LENGTH);
        this.argon2HashFunction = argon2HashFunction;
    }

    @Override
    public String encode(String rawPassword) {
        if (!StringUtils.hasText(rawPassword)) {
            throw new IllegalArgumentException("The raw password must not be blank");
        }
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        byte[] hash = argon2HashFunction.hash(rawPassword, salt, memory, iterations, parallelism, hashLength);
        return Argon2PhcString.format(memory, iterations, parallelism, salt, hash);
    }

    @Override
    public boolean matches(String rawPassword, String encodedPassword) {
        if (!StringUtils.hasText(rawPassword) || !StringUtils.hasText(encodedPassword)) {
            return false;
        }
        Argon2PhcString phc = Argon2PhcString.parse(encodedPassword);
        if (phc == null) {
            return false;
        }
        if (phc.memory() > maxMemory || phc.iterations() > maxIterations) {
            LOG.warn("An encoded password was rejected because its Argon2 parameters exceed the configured max-memory or max-iterations");
            return false;
        }
        if (phc.memory() < (long) MEMORY_PER_LANE * phc.parallelism()) {
            return false;
        }
        byte[] hash = argon2HashFunction.hash(rawPassword, phc);
        return MessageDigest.isEqual(phc.hash(), hash);
    }

    private static int requireRange(String property, int value, int min, int max) {
        if (value < min || value > max) {
            throw new ConfigurationException(Argon2PasswordEncoderConfigurationProperties.PREFIX + "." + property
                + " must be between " + min + " and " + max + " but was " + value);
        }
        return value;
    }
}
