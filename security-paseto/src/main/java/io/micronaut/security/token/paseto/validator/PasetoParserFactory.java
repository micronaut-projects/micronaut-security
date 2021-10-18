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
        if (configuration.getRequiredClaimsPredicate() != null) {
            for (String claimName : configuration.getRequiredClaimsPredicate().keySet()) {
                builder = builder.require(claimName, configuration.getRequiredClaimsPredicate().get(claimName));
            }
        }
        if (configuration.getRequiredClaimsValue() != null) {
            for (String claimName : configuration.getRequiredClaimsValue().keySet()) {
                builder = builder.require(claimName, configuration.getRequiredClaimsValue().get(claimName));
            }
        }
        if (configuration.getRequiredFooterPredicate() != null) {
            for (String claimName : configuration.getRequiredFooterPredicate().keySet()) {
                builder = builder.requireFooter(claimName, configuration.getRequiredFooterPredicate().get(claimName));
            }
        }
        return builder;
    }
}
