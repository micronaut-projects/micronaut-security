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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * {@link BiscuitConfiguration} implementation.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@ConfigurationProperties(BiscuitConfigurationProperties.PREFIX)
public class BiscuitConfigurationProperties implements BiscuitConfiguration {

    /**
     * Biscuit configuration prefix.
     */
    public static final String PREFIX = BiscuitConfiguration.PREFIX;

    /**
     * Default enablement.
     */
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * Default validator enablement.
     */
    public static final boolean DEFAULT_VALIDATOR_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;
    private boolean validatorEnabled = DEFAULT_VALIDATOR_ENABLED;
    @Nullable
    private String rootPublicKey;
    @Nullable
    private Integer rootKeyId;
    private List<String> facts = new ArrayList<>();
    private List<String> rules = new ArrayList<>();
    private List<String> checks = new ArrayList<>();
    private List<String> policies = new ArrayList<>();
    private Set<String> revokedIdentifiers = new HashSet<>();
    private RunLimitsConfigurationProperties runLimits = new RunLimitsConfigurationProperties();
    private AuthenticationConfigurationProperties authentication = new AuthenticationConfigurationProperties();

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether Biscuit support is enabled. Default value ({@value #DEFAULT_ENABLED}).
     * @param enabled True if enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean isValidatorEnabled() {
        return validatorEnabled;
    }

    /**
     * Sets whether the Biscuit token validator is enabled. Default value ({@value #DEFAULT_VALIDATOR_ENABLED}).
     * @param validatorEnabled True if enabled
     */
    public void setValidatorEnabled(boolean validatorEnabled) {
        this.validatorEnabled = validatorEnabled;
    }

    @Override
    @Nullable
    public String getRootPublicKey() {
        return rootPublicKey;
    }

    /**
     * Sets the Ed25519 root public key in hexadecimal form.
     * @param rootPublicKey The root public key
     */
    public void setRootPublicKey(@Nullable String rootPublicKey) {
        this.rootPublicKey = rootPublicKey;
    }

    @Override
    @Nullable
    public Integer getRootKeyId() {
        return rootKeyId;
    }

    /**
     * Sets the optional root key identifier for the configured root public key.
     * @param rootKeyId The root key identifier
     */
    public void setRootKeyId(@Nullable Integer rootKeyId) {
        this.rootKeyId = rootKeyId;
    }

    @Override
    public List<String> getFacts() {
        return facts;
    }

    /**
     * Sets authorizer facts added before customizers run.
     * @param facts The facts
     */
    public void setFacts(List<String> facts) {
        this.facts = facts;
    }

    @Override
    public List<String> getRules() {
        return rules;
    }

    /**
     * Sets authorizer rules added before customizers run.
     * @param rules The rules
     */
    public void setRules(List<String> rules) {
        this.rules = rules;
    }

    @Override
    public List<String> getChecks() {
        return checks;
    }

    /**
     * Sets authorizer checks added before customizers run.
     * @param checks The checks
     */
    public void setChecks(List<String> checks) {
        this.checks = checks;
    }

    @Override
    public List<String> getPolicies() {
        return policies;
    }

    /**
     * Sets authorizer policies added before customizers run.
     * @param policies The policies
     */
    public void setPolicies(List<String> policies) {
        this.policies = policies;
    }

    @Override
    public Set<String> getRevokedIdentifiers() {
        return revokedIdentifiers;
    }

    /**
     * Sets revocation identifiers that must be rejected.
     * @param revokedIdentifiers The revoked identifiers
     */
    public void setRevokedIdentifiers(Set<String> revokedIdentifiers) {
        this.revokedIdentifiers = revokedIdentifiers;
    }

    @Override
    public RunLimitsConfigurationProperties getRunLimits() {
        return runLimits;
    }

    /**
     * Sets Datalog run limits.
     * @param runLimits The run limits
     */
    public void setRunLimits(RunLimitsConfigurationProperties runLimits) {
        this.runLimits = runLimits;
    }

    @Override
    public AuthenticationConfigurationProperties getAuthentication() {
        return authentication;
    }

    /**
     * Sets authentication mapping configuration.
     * @param authentication The authentication configuration
     */
    public void setAuthentication(AuthenticationConfigurationProperties authentication) {
        this.authentication = authentication;
    }

    /**
     * Datalog run limit configuration.
     */
    @ConfigurationProperties("run-limits")
    public static class RunLimitsConfigurationProperties implements RunLimitsConfiguration {

        /**
         * Default maximum generated facts.
         */
        public static final int DEFAULT_MAX_FACTS = 1000;

        /**
         * Default maximum Datalog iterations.
         */
        public static final int DEFAULT_MAX_ITERATIONS = 100;

        /**
         * Default maximum authorization time.
         */
        public static final Duration DEFAULT_MAX_TIME = Duration.ofMillis(50);

        private int maxFacts = DEFAULT_MAX_FACTS;
        private int maxIterations = DEFAULT_MAX_ITERATIONS;
        private Duration maxTime = DEFAULT_MAX_TIME;

        @Override
        public int getMaxFacts() {
            return maxFacts;
        }

        /**
         * Sets the maximum generated facts. Default value ({@value #DEFAULT_MAX_FACTS}).
         * @param maxFacts The maximum generated facts
         */
        public void setMaxFacts(int maxFacts) {
            this.maxFacts = maxFacts;
        }

        @Override
        public int getMaxIterations() {
            return maxIterations;
        }

        /**
         * Sets the maximum Datalog iterations. Default value ({@value #DEFAULT_MAX_ITERATIONS}).
         * @param maxIterations The maximum Datalog iterations
         */
        public void setMaxIterations(int maxIterations) {
            this.maxIterations = maxIterations;
        }

        @Override
        public Duration getMaxTime() {
            return maxTime;
        }

        /**
         * Sets the maximum authorization time. Default value is fifty milliseconds.
         * @param maxTime The maximum authorization time
         */
        public void setMaxTime(Duration maxTime) {
            this.maxTime = maxTime;
        }
    }

    /**
     * Default authentication mapping configuration.
     */
    @ConfigurationProperties("authentication")
    public static class AuthenticationConfigurationProperties implements AuthenticationConfiguration {

        /**
         * Default query used to find the authenticated principal.
         */
        public static final String DEFAULT_PRINCIPAL_QUERY = "principal($name) <- principal($name)";

        /**
         * Default query used to find granted roles.
         */
        public static final String DEFAULT_ROLES_QUERY = "role($role) <- role($role)";

        private String principalQuery = DEFAULT_PRINCIPAL_QUERY;
        private String rolesQuery = DEFAULT_ROLES_QUERY;

        @Override
        public String getPrincipalQuery() {
            return principalQuery;
        }

        /**
         * Sets the query used to find the authenticated principal.
         * @param principalQuery The principal query
         */
        public void setPrincipalQuery(String principalQuery) {
            this.principalQuery = principalQuery;
        }

        @Override
        public String getRolesQuery() {
            return rolesQuery;
        }

        /**
         * Sets the query used to find granted roles.
         * @param rolesQuery The roles query
         */
        public void setRolesQuery(String rolesQuery) {
            this.rolesQuery = rolesQuery;
        }
    }
}
