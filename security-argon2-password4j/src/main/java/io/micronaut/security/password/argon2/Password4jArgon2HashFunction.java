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
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.password.PasswordEncoder;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import java.nio.charset.StandardCharsets;

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
@Named(Password4jArgon2HashFunction.NAME)
final class Password4jArgon2HashFunction implements Argon2HashFunction {
    static final String NAME = "password4j";
    private static final int VERSION = 19;

    @Override
    public byte[] hash(String rawPassword, byte[] salt, int memory, int iterations, int parallelism, int hashLength) {
        return Argon2Function.getInstance(memory, iterations, parallelism, hashLength, Argon2.ID, VERSION)
            .hash(rawPassword.getBytes(StandardCharsets.UTF_8), salt)
            .getBytes();
    }

    @Override
    public String getName() {
        return NAME;
    }
}
