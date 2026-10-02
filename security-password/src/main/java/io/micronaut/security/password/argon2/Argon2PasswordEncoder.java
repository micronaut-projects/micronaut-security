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

import io.micronaut.context.annotation.EachBean;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.SecureRandom;

import static io.micronaut.security.password.argon2.Argon2PhcString.MEMORY_PER_LANE;

/**
 * {@link PasswordEncoder} that applies the Argon2id password policy and PHC string handling shared
 * by the hash implementations, and delegates the hash operation to an {@link Argon2HashFunction}.
 */
@EachBean(Argon2HashFunction.class)
@Internal
class Argon2PasswordEncoder implements PasswordEncoder {
    private static final Logger LOG = LoggerFactory.getLogger(Argon2PasswordEncoder.class);
    private final SecureRandom secureRandom = new SecureRandom();
    private final Argon2HashFunction argon2HashFunction;
    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final int saltLength;
    private final int hashLength;
    private final int maxMemory;
    private final int maxIterations;

    /**
     * @param configuration the Argon2id configuration
     * @param argon2HashFunction the Argon2 hash function
     */
    Argon2PasswordEncoder(Argon2PasswordEncoderConfiguration configuration, Argon2HashFunction argon2HashFunction) {
        this.argon2HashFunction = argon2HashFunction;
        this.memory = configuration.getMemory();
        this.iterations = configuration.getIterations();
        this.parallelism = configuration.getParallelism();
        this.saltLength = configuration.getSaltLength();
        this.hashLength = configuration.getHashLength();
        this.maxMemory = configuration.getMaxMemory();
        this.maxIterations = configuration.getMaxIterations();
    }

    @Override
    public String encode(@NotBlank String rawPassword) {
        if (!StringUtils.hasText(rawPassword)) {
            throw new IllegalArgumentException("The raw password must not be blank");
        }
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        byte[] hash = argon2HashFunction.hash(rawPassword, salt, memory, iterations, parallelism, hashLength);
        return Argon2PhcString.format(memory, iterations, parallelism, salt, hash);
    }

    @Override
    public boolean matches(@NotBlank String rawPassword, @NotBlank String encodedPassword) {
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
        // the checks above keep the memory and iterations within the configured int limits
        byte[] hash = argon2HashFunction.hash(rawPassword, phc.salt(), Math.toIntExact(phc.memory()),
            Math.toIntExact(phc.iterations()), phc.parallelism(), phc.hash().length);
        return MessageDigest.isEqual(phc.hash(), hash);
    }

}
