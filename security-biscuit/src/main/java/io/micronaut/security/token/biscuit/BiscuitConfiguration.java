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
package io.micronaut.security.token.biscuit;

import io.micronaut.security.token.config.TokenConfigurationProperties;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Configuration for Biscuit token validation.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
public interface BiscuitConfiguration {

    /**
     * Biscuit configuration prefix.
     */
    String PREFIX = TokenConfigurationProperties.PREFIX + ".biscuit";

    /**
     * @return Whether Biscuit support is enabled.
     */
    boolean isEnabled();

    /**
     * @return Whether the Biscuit token validator is enabled.
     */
    boolean isValidatorEnabled();

    /**
     * @return The configured Ed25519 root public key in hexadecimal form.
     */
    @Nullable
    String getRootPublicKey();

    /**
     * @return Optional root key identifier for the configured root public key.
     */
    @Nullable
    Integer getRootKeyId();

    /**
     * @return Authorizer facts added before customizers run.
     */
    List<String> getFacts();

    /**
     * @return Authorizer rules added before customizers run.
     */
    List<String> getRules();

    /**
     * @return Authorizer checks added before customizers run.
     */
    List<String> getChecks();

    /**
     * @return Authorizer policies added before customizers run.
     */
    List<String> getPolicies();

    /**
     * @return Revocation identifiers that must be rejected.
     */
    Set<String> getRevokedIdentifiers();

    /**
     * @return Datalog run limit configuration.
     */
    RunLimitsConfiguration getRunLimits();

    /**
     * @return Default authentication mapping configuration.
     */
    AuthenticationConfiguration getAuthentication();

    /**
     * Biscuit Datalog run limits.
     */
    interface RunLimitsConfiguration {

        /**
         * @return Maximum generated facts.
         */
        int getMaxFacts();

        /**
         * @return Maximum Datalog iterations.
         */
        int getMaxIterations();

        /**
         * @return Maximum authorization time.
         */
        Duration getMaxTime();
    }

    /**
     * Default authentication mapping configuration.
     */
    interface AuthenticationConfiguration {

        /**
         * @return Query used to find the authenticated principal.
         */
        String getPrincipalQuery();

        /**
         * @return Query used to find granted roles.
         */
        String getRolesQuery();
    }
}
