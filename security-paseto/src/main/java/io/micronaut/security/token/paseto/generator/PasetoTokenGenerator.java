/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.security.token.paseto.generator;

import dev.paseto.jpaseto.PasetoBuilder;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.claims.ClaimsGenerator;
import jakarta.inject.Singleton;
import java.util.Map;
import java.util.Optional;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class PasetoTokenGenerator implements TokenGenerator {

    protected final ClaimsGenerator claimsGenerator;
    private final PasetoBuilderGenerator pasetoBuilderGenerator;

    /**
     *
     * @param claimsGenerator Claims Generator
     * @param pasetoBuilderGenerator Paseto Builder Generator
     */
    public PasetoTokenGenerator(ClaimsGenerator claimsGenerator,
                                PasetoBuilderGenerator pasetoBuilderGenerator) {
        this.claimsGenerator = claimsGenerator;
        this.pasetoBuilderGenerator = pasetoBuilderGenerator;
    }

    /**
     * Generate a Paseto from a map of claims.
     *
     * @param claims the map of claims
     * @return the created Paseto
     */
    private String generate(final Map<String, Object> claims) {
        final PasetoBuilder<?> builder = pasetoBuilderGenerator.builder();
        for (final Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }
        return builder.compact();
    }

    @Override
    public Optional<String> generateToken(Authentication authentication, Integer expiration) {
        return generateToken(claimsGenerator.generateClaims(authentication, expiration));
    }

    @Override
    public Optional<String> generateToken(Map<String, Object> claims) {
        return Optional.of(generate(claims));
    }
}
