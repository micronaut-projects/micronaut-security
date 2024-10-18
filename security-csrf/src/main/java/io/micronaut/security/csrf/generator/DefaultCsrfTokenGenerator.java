/*
 * Copyright 2017-2024 original authors
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
package io.micronaut.security.csrf.generator;

import io.micronaut.core.annotation.Internal;
import io.micronaut.security.csrf.CsrfConfiguration;
import jakarta.inject.Singleton;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Default implementation of {@link CsrfTokenGenerator} which generates a random base 64 encoded string using an instance of {@link SecureRandom} and random byte array of size {@link CsrfConfiguration#getTokenSize()}.
 * @author Sergio del Amo
 * @since 4.11.0
 */
@Singleton
@Internal
final class DefaultCsrfTokenGenerator implements CsrfTokenGenerator {

    private final SecureRandom secureRandom = new SecureRandom();
    private final CsrfConfiguration csrfConfiguration;

    DefaultCsrfTokenGenerator(CsrfConfiguration csrfConfiguration) {
        this.csrfConfiguration = csrfConfiguration;
    }

    @Override
    public String generate() {
        byte[] tokenBytes = new byte[csrfConfiguration.getTokenSize()];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
