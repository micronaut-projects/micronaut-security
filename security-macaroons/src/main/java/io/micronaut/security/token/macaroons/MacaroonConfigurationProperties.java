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

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.security.token.config.TokenConfigurationProperties;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link MacaroonConfiguration} implementation.
 *
 * @author Sergio del Amo
 * @since 5.1.0
 */
@Requires(property = TokenConfigurationProperties.PREFIX + ".enabled", notEquals = StringUtils.FALSE)
@ConfigurationProperties(MacaroonConfigurationProperties.PREFIX)
public class MacaroonConfigurationProperties implements MacaroonConfiguration {

    /**
     * The configuration prefix.
     */
    public static final String PREFIX = TokenConfigurationProperties.PREFIX + ".macaroons";

    /**
     * The default enabled value.
     */
    public static final boolean DEFAULT_ENABLED = true;

    /**
     * The default generator enabled value.
     */
    public static final boolean DEFAULT_GENERATOR_ENABLED = true;

    /**
     * The default validator enabled value.
     */
    public static final boolean DEFAULT_VALIDATOR_ENABLED = true;

    /**
     * The default location.
     */
    public static final String DEFAULT_LOCATION = "micronaut";

    /**
     * The default identifier.
     */
    public static final String DEFAULT_IDENTIFIER = "micronaut-security-macaroon";

    private boolean enabled = DEFAULT_ENABLED;
    private boolean generatorEnabled = DEFAULT_GENERATOR_ENABLED;
    private boolean validatorEnabled = DEFAULT_VALIDATOR_ENABLED;
    @Nullable
    private String secret;
    private String location = DEFAULT_LOCATION;
    private String identifier = DEFAULT_IDENTIFIER;
    private MacaroonSerialization serialization = MacaroonSerialization.V2;
    private List<MacaroonSerialization> acceptedSerializations = new ArrayList<>(List.of(MacaroonSerialization.V2, MacaroonSerialization.V1));
    private List<String> caveats = new ArrayList<>();

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether Macaroon support is enabled.
     *
     * @param enabled True if Macaroon support is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean isGeneratorEnabled() {
        return generatorEnabled;
    }

    /**
     * Sets whether the Macaroon token generator bean is enabled.
     *
     * @param generatorEnabled True if the generator is enabled
     */
    public void setGeneratorEnabled(boolean generatorEnabled) {
        this.generatorEnabled = generatorEnabled;
    }

    @Override
    public boolean isValidatorEnabled() {
        return validatorEnabled;
    }

    /**
     * Sets whether the Macaroon token validator bean is enabled.
     *
     * @param validatorEnabled True if the validator is enabled
     */
    public void setValidatorEnabled(boolean validatorEnabled) {
        this.validatorEnabled = validatorEnabled;
    }

    @Override
    @Nullable
    public String getSecret() {
        return secret;
    }

    /**
     * Sets the root secret used to sign and verify Macaroons.
     *
     * @param secret The root secret
     */
    public void setSecret(@Nullable String secret) {
        this.secret = secret;
    }

    @Override
    public String getLocation() {
        return location;
    }

    /**
     * Sets the location written into generated Macaroons.
     *
     * @param location The location
     */
    public void setLocation(String location) {
        if (StringUtils.isNotEmpty(location)) {
            this.location = location;
        }
    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Sets the identifier written into generated Macaroons.
     *
     * @param identifier The identifier
     */
    public void setIdentifier(String identifier) {
        if (StringUtils.isNotEmpty(identifier)) {
            this.identifier = identifier;
        }
    }

    @Override
    public MacaroonSerialization getSerialization() {
        return serialization;
    }

    /**
     * Sets the serialization format used by generated Macaroons.
     *
     * @param serialization The serialization format
     */
    public void setSerialization(MacaroonSerialization serialization) {
        this.serialization = serialization;
    }

    @Override
    public List<MacaroonSerialization> getAcceptedSerializations() {
        return acceptedSerializations;
    }

    /**
     * Sets the serialization formats accepted by the validator.
     *
     * @param acceptedSerializations The accepted formats
     */
    public void setAcceptedSerializations(List<MacaroonSerialization> acceptedSerializations) {
        if (!acceptedSerializations.isEmpty()) {
            this.acceptedSerializations = new ArrayList<>(acceptedSerializations);
        }
    }

    @Override
    public List<String> getCaveats() {
        return caveats;
    }

    /**
     * Sets additional first-party caveats added to generated Macaroons.
     *
     * @param caveats The caveats
     */
    public void setCaveats(List<String> caveats) {
        this.caveats = new ArrayList<>(caveats);
    }
}
