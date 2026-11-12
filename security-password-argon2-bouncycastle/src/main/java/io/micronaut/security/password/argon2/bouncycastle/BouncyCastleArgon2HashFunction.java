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
package io.micronaut.security.password.argon2.bouncycastle;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.password.argon2.Argon2HashFunction;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id password encoder implemented with Bouncy Castle.
 *
 * <p>Encoded passwords use PHC strings and include the parameters needed for verification.</p>
 */
@Singleton
@Internal
@Named(BouncyCastleArgon2HashFunction.NAME)
final class BouncyCastleArgon2HashFunction implements Argon2HashFunction {
    static final String NAME = "bouncycastle";

    @Override
    public byte[] hash(String rawPassword, byte[] salt, int memory, int iterations, int parallelism, int hashLength) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(memory)
            .withIterations(iterations)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build();
        // The generator keeps mutable working memory, so each hash call owns its own instance.
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(parameters);
        byte[] hash = new byte[hashLength];
        // The char[] variant encodes the password as UTF-8 and fails on an unpaired surrogate, where
        // String#getBytes would replace it with '?' and make different passwords hash alike.
        generator.generateBytes(rawPassword.toCharArray(), hash);
        return hash;
    }

    @Override
    public String getName() {
        return NAME;
    }
}
