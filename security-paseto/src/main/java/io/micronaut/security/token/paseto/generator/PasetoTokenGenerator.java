/*
 * Copyright 2017-2020 original authors
 *
 *  Licensed under the Apache License, Version 2.0 \(the "License"\);
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package io.micronaut.security.token.paseto.generator;

import dev.paseto.jpaseto.PasetoBuilder;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.Purpose;
import dev.paseto.jpaseto.Version;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.generator.TokenGenerator;
import io.micronaut.security.token.paseto.generator.claims.ClaimsGenerator;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

/**
 * @author Utsav Varia
 * @since 3.0
 */
@Singleton
public class PasetoTokenGenerator implements TokenGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(PasetoTokenGenerator.class);

    protected final ClaimsGenerator claimsGenerator;
    protected final PasetoTokenConfigurationProperties tokenConfigurationProperties;

    public PasetoTokenGenerator(ClaimsGenerator claimsGenerator, PasetoTokenConfigurationProperties tokenConfigurationProperties) {
        this.claimsGenerator = claimsGenerator;
        this.tokenConfigurationProperties = tokenConfigurationProperties;
    }

    /**
     * Returns Paseto Token builder based on configuration.
     *
     * @return Paseto Builder
     */
    public PasetoBuilder<?> getPasetoBuilder() {
        if (Version.V1.equals(tokenConfigurationProperties.getVersion())) {
            if (Purpose.LOCAL.equals(tokenConfigurationProperties.getPurpose())) {
                return Pasetos.V1.LOCAL.builder().setSharedSecret(tokenConfigurationProperties.getSecretKey());
            } else {
                return Pasetos.V1.PUBLIC.builder();
            }
        } else {
            if (Purpose.LOCAL.equals(tokenConfigurationProperties.getPurpose())) {
                return Pasetos.V2.LOCAL.builder().setSharedSecret(tokenConfigurationProperties.getSecretKey());
            } else {
                return Pasetos.V2.PUBLIC.builder();
            }
        }
    }

    /**
     * Generate a JWT from a map of claims.
     *
     * @param claims the map of claims
     * @return the created JWT
     */
    protected String generate(final Map<String, Object> claims) {
        // claims builder
        final PasetoBuilder<?> builder = getPasetoBuilder();

        // add claims
        for (final Map.Entry<String, Object> entry : claims.entrySet()) {
            builder.claim(entry.getKey(), entry.getValue());
        }

        return builder.compact();
    }

    @Override
    public Optional<String> generateToken(Authentication authentication, Integer expiration) {
        Map<String, Object> claims = claimsGenerator.generateClaims(authentication, expiration);
        return generateToken(claims);
    }

    @Override
    public Optional<String> generateToken(Map<String, Object> claims) {
        return Optional.of(generate(claims));
    }
}
