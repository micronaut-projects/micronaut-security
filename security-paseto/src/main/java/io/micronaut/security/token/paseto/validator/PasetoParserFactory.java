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
package io.micronaut.security.token.paseto.validator;

import dev.paseto.jpaseto.PasetoParser;
import dev.paseto.jpaseto.PasetoParserBuilder;
import dev.paseto.jpaseto.Pasetos;
import io.micronaut.context.annotation.EachBean;
import io.micronaut.context.annotation.Factory;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.security.token.paseto.config.PublicKeyConfiguration;
import io.micronaut.security.token.paseto.config.RequiredConfiguration;
import io.micronaut.security.token.paseto.config.SharedSecretConfiguration;
import jakarta.inject.Singleton;

import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Predicate;

/**
 * {@link Factory} to generate beans of type {@link PasetoParser} for beans of type {@link PublicKeyConfiguration} or {@link SharedSecretConfiguration}.
 * @author Sergio del Amo
 * @since 3.2.0
 */
@Factory
public class PasetoParserFactory {
    /**
     *
     * @param configuration Paseto Public Key Configuration
     * @return A Paseto Parser
     */
    @EachBean(PublicKeyConfiguration.class)
    @Singleton
    PasetoParser pasetoParserWithPublicKey(PublicKeyConfiguration configuration) {
        PasetoParserBuilder builder = Pasetos.parserBuilder()
                .setPublicKey(configuration.getPublicKey());
        builder = populateBuilder(builder, configuration);
        return builder.build();
    }

    /**
     *
     * @param configuration Shared Key configuration
     * @return A Paseto Parser
     */
    @EachBean(SharedSecretConfiguration.class)
    @Singleton
    PasetoParser pasetoParserWithSharedSecretConfiguration(SharedSecretConfiguration configuration) {
        PasetoParserBuilder builder = Pasetos.parserBuilder()
                .setSharedSecret(configuration.getSharedSecret());
        builder = populateBuilder(builder, configuration);
        return builder.build();
    }

    @NonNull
    private PasetoParserBuilder populateBuilder(@NonNull PasetoParserBuilder builder,
                                                @NonNull RequiredConfiguration configuration) {
        builder = populateRequiredStandardClaims(builder, configuration);
        builder = populateRequiredClaimPredicates(builder, configuration.getRequiredClaimsPredicate(), PasetoParserFactory::require);
        builder = populateRequiredClaimValues(builder, configuration.getRequiredClaimsValue());
        return populateRequiredClaimPredicates(builder, configuration.getRequiredFooterPredicate(), PasetoParserFactory::requireFooter);
    }

    @NonNull
    private PasetoParserBuilder populateRequiredStandardClaims(@NonNull PasetoParserBuilder builder,
                                                               @NonNull RequiredConfiguration configuration) {
        if (configuration.getRequiredAudience() != null) {
            builder = builder.requireAudience(configuration.getRequiredAudience());
        }
        if (configuration.getRequiredIssuer() != null) {
            builder = builder.requireIssuer(configuration.getRequiredIssuer());
        }
        if (configuration.getRequiredKeyId() != null) {
            builder = builder.requireKeyId(configuration.getRequiredKeyId());
        }
        if (configuration.getRequiredSubject() != null) {
            builder = builder.requireSubject(configuration.getRequiredSubject());
        }
        if (configuration.getRequiredTokenId() != null) {
            builder = builder.requireTokenId(configuration.getRequiredTokenId());
        }
        if (configuration.getRequiredExpiration() != null) {
            builder = builder.requireExpiration(configuration.getRequiredExpiration());
        }
        if (configuration.getRequiredIssuedAt() != null) {
            builder = builder.requireIssuedAt(configuration.getRequiredIssuedAt());
        }
        if (configuration.getRequiredNotBefore() != null) {
            builder = builder.requireNotBefore(configuration.getRequiredNotBefore());
        }
        return builder;
    }

    @NonNull
    private PasetoParserBuilder populateRequiredClaimValues(@NonNull PasetoParserBuilder builder,
                                                            Map<String, Object> requiredClaims) {
        if (requiredClaims != null) {
            for (Map.Entry<String, Object> claim : requiredClaims.entrySet()) {
                builder = builder.require(claim.getKey(), claim.getValue());
            }
        }
        return builder;
    }

    @NonNull
    private PasetoParserBuilder populateRequiredClaimPredicates(@NonNull PasetoParserBuilder builder,
                                                                Map<String, Predicate<Object>> requiredClaims,
                                                                BiFunction<PasetoParserBuilder, Map.Entry<String, Predicate<Object>>, PasetoParserBuilder> require) {
        if (requiredClaims != null) {
            for (Map.Entry<String, Predicate<Object>> claim : requiredClaims.entrySet()) {
                builder = require.apply(builder, claim);
            }
        }
        return builder;
    }

    @NonNull
    private static PasetoParserBuilder require(@NonNull PasetoParserBuilder builder,
                                               @NonNull Map.Entry<String, Predicate<Object>> claim) {
        return builder.require(claim.getKey(), claim.getValue());
    }

    @NonNull
    private static PasetoParserBuilder requireFooter(@NonNull PasetoParserBuilder builder,
                                                     @NonNull Map.Entry<String, Predicate<Object>> claim) {
        return builder.requireFooter(claim.getKey(), claim.getValue());
    }
}
