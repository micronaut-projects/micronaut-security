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
package io.micronaut.security.token.macaroons;

import com.github.nitram509.jmacaroons.Macaroon;
import com.github.nitram509.jmacaroons.MacaroonsBuilder;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.annotation.Secondary;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.token.claims.ClaimsGenerator;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import io.micronaut.security.token.generator.TokenGenerator;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;

import static io.micronaut.security.utils.LoggingUtils.debug;

/**
 * Macaroon token generator.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".generator-enabled", notEquals = StringUtils.FALSE)
@Requires(property = MacaroonConfigurationProperties.PREFIX + ".secret")
@Secondary
@Singleton
public class MacaroonTokenGenerator implements TokenGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(MacaroonTokenGenerator.class);

    private final MacaroonConfiguration configuration;
    private final ClaimsGenerator claimsGenerator;

    /**
     * @param configuration Macaroon configuration
     * @param claimsGenerator Claims generator
     */
    public MacaroonTokenGenerator(MacaroonConfiguration configuration,
                                  ClaimsGenerator claimsGenerator) {
        this.configuration = configuration;
        this.claimsGenerator = claimsGenerator;
    }

    @Override
    public Optional<String> generateToken(Authentication authentication, @Nullable Integer expiration) {
        return generateToken(claimsGenerator.generateClaims(authentication, expiration));
    }

    @Override
    public Optional<String> generateToken(Map<String, Object> claims) {
        @Nullable String configuredSecret = configuration.getSecret();
        if (configuredSecret == null || configuredSecret.isEmpty()) {
            debug(LOG, "Macaroon token generation skipped because no root secret is configured");
            return Optional.empty();
        }
        Optional<java.util.List<String>> claimCaveats = MacaroonClaimsCodec.encodeClaims(claims);
        if (claimCaveats.isEmpty()) {
            debug(LOG, "Macaroon token generation skipped because one or more claims cannot be encoded safely");
            return Optional.empty();
        }
        try {
            MacaroonsBuilder builder = Macaroon.builder(configuration.getLocation(), configuredSecret, configuration.getIdentifier());
            for (String caveat : claimCaveats.get()) {
                builder.addCaveat(caveat);
            }
            for (String caveat : configuration.getCaveats()) {
                if (StringUtils.isNotEmpty(caveat)) {
                    builder.addCaveat(caveat);
                }
            }
            Macaroon macaroon = builder.build();
            return Optional.of(macaroon.serialize(MacaroonSerializers.serializer(configuration.getSerialization())));
        } catch (RuntimeException e) {
            debug(LOG, "Macaroon token generation failed: {}", e.getClass().getSimpleName());
            return Optional.empty();
        }
    }
}
