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

import com.password4j.Argon2Function;
import com.password4j.types.Argon2;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.core.annotation.Internal;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * {@link PasswordEncoder} that hashes passwords with Argon2id and stores them as PHC strings.
 *
 * <p>A password is verified with the parameters declared in its encoded form, so passwords encoded
 * with previous settings keep matching after the configuration changes.</p>
 *
 * @since 5.5.0
 */
@Singleton
@Internal
class Argon2PasswordEncoder implements PasswordEncoder {

    private static final Logger LOG = LoggerFactory.getLogger(Argon2PasswordEncoder.class);
    private static final int VERSION = 19;
    // Argon2 requires at least 8 kibibytes of memory per lane.
    private static final int MEMORY_PER_LANE = 8;

    private final int memory;
    private final int iterations;
    private final int parallelism;
    private final int saltLength;
    private final int hashLength;
    private final int maxMemory;
    private final int maxIterations;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * @param configuration the Argon2id configuration
     */
    Argon2PasswordEncoder(Argon2PasswordEncoderConfiguration configuration) {
        this.parallelism = requireRange("parallelism", configuration.getParallelism(), 1, Argon2PhcString.MAX_PARALLELISM);
        this.maxMemory = configuration.getMaxMemory();
        this.maxIterations = configuration.getMaxIterations();
        this.memory = requireRange("memory", configuration.getMemory(), MEMORY_PER_LANE * parallelism, maxMemory);
        this.iterations = requireRange("iterations", configuration.getIterations(), 1, maxIterations);
        this.saltLength = requireRange("salt-length", configuration.getSaltLength(), Argon2PhcString.MIN_SALT_LENGTH, Argon2PhcString.MAX_SALT_LENGTH);
        this.hashLength = requireRange("hash-length", configuration.getHashLength(), Argon2PhcString.MIN_HASH_LENGTH, Argon2PhcString.MAX_HASH_LENGTH);
    }

    @Override
    public String encode(String rawPassword) {
        if (!StringUtils.hasText(rawPassword)) {
            throw new IllegalArgumentException("The raw password must not be blank");
        }
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);
        byte[] hash = hash(rawPassword, salt, memory, iterations, parallelism, hashLength);
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
        byte[] hash = hash(rawPassword, phc.salt(), (int) phc.memory(), (int) phc.iterations(), phc.parallelism(), phc.hash().length);
        return MessageDigest.isEqual(phc.hash(), hash);
    }

    private static byte[] hash(String rawPassword, byte[] salt, int memory, int iterations, int parallelism, int hashLength) {
        return Argon2Function.getInstance(memory, iterations, parallelism, hashLength, Argon2.ID, VERSION)
            .hash(rawPassword.getBytes(StandardCharsets.UTF_8), salt)
            .getBytes();
    }

    private static int requireRange(String property, int value, int min, int max) {
        if (value < min || value > max) {
            throw new ConfigurationException(Argon2PasswordEncoderConfigurationProperties.PREFIX + "." + property
                + " must be between " + min + " and " + max + " but was " + value);
        }
        return value;
    }
}
