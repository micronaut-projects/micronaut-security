/*
 * Copyright 2017-2022 original authors
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
package io.micronaut.security.oauth2.endpoint.authorization.pkce;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.configuration.OauthConfigurationProperties;
import reactor.util.annotation.NonNull;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import java.util.Optional;

/**
 * Configuration properties implementation of PKCE.
 *
 * @author Nemanja Mikic
 * @since 3.9.0
 */
@ConfigurationProperties(PkceConfigurationProperties.PREFIX)
public class PkceConfigurationProperties implements PkceConfiguration {
    public static final String PREFIX = OauthConfigurationProperties.PREFIX + ".pkce";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;
    public static final String PERSISTENCE_COOKIE = "cookie";
    public static final String PERSISTENCE_SESSION = "session";

    /**
     * The minimum entropy (in bytes) allowed for the code verifier. 32 bytes produce the 43 character minimum
     * code verifier length mandated by <a href="https://datatracker.ietf.org/doc/html/rfc7636#section-4.1">RFC 7636 Section 4.1</a>.
     */
    public static final int MIN_CODE_VERIFIER_ENTROPY = 32;

    /**
     * The maximum entropy (in bytes) allowed for the code verifier. 96 bytes produce the 128 character maximum
     * code verifier length mandated by <a href="https://datatracker.ietf.org/doc/html/rfc7636#section-4.1">RFC 7636 Section 4.1</a>.
     */
    public static final int MAX_CODE_VERIFIER_ENTROPY = 96;

    private static final String DEFAULT_PERSISTENCE = PERSISTENCE_COOKIE;

    /**
     * The default entropy (in bytes) used for the code verifier.
     */
    private static final int DEFAULT_CODE_VERIFIER_ENTROPY = 64;

    private String persistence = DEFAULT_PERSISTENCE;
    private boolean enabled = DEFAULT_ENABLED;
    private int entropy = DEFAULT_CODE_VERIFIER_ENTROPY;

    @Override
    @Min(MIN_CODE_VERIFIER_ENTROPY)
    @Max(MAX_CODE_VERIFIER_ENTROPY)
    public int getEntropy() {
        return entropy;
    }

    /**
     * Entropy (in bytes) used for the code verifier generation. Must be between {@value #MIN_CODE_VERIFIER_ENTROPY} and {@value #MAX_CODE_VERIFIER_ENTROPY} (inclusive)
     * so that the Base64 URL-encoded code verifier is between 43 and 128 characters long as required by RFC 7636. Default value {@value #DEFAULT_CODE_VERIFIER_ENTROPY}.
     * @param entropy entropy (in bytes) used for the code verifier.
     */
    public void setEntropy(int entropy) {
        this.entropy = entropy;
    }

    @Override
    @NonNull
    public Optional<@Pattern(regexp = "cookie|session") String> getPersistence() {
        return Optional.ofNullable(persistence);
    }

    /**
     * Sets the mechanism to persist the state for later retrieval for validation.
     * Supported values ("session", "cookie"). Default value ({@value #DEFAULT_PERSISTENCE}).
     *
     * @param persistence The persistence mechanism
     */
    public void setPersistence(String persistence) {
        this.persistence = persistence;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether a state parameter will be sent. Default ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled The enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
