package io.micronaut.security.oauth2.openid.endpoints.authorization.state.validation;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.security.oauth2.openid.configuration.OpenIdProviderConfigurationProperties;
import io.micronaut.security.oauth2.openid.endpoints.authorization.state.OpenIdStateConfiguration;

import javax.annotation.Nonnull;
import java.util.Optional;

@ConfigurationProperties(DefaultStateValidationConfiguration.PREFIX)
public class DefaultStateValidationConfiguration implements StateValidationConfiguration {

    public static final String PREFIX = OpenIdProviderConfigurationProperties.PREFIX + ".state.validation";

    private static final boolean DEFAULT_ENABLED = true;

    private String persistence;
    private boolean enabled = DEFAULT_ENABLED;

    @Override
    @Nonnull
    public Optional<String> getPersistence() {
        return Optional.ofNullable(persistence);
    }

    /**
     * Sets the mechanism to persist the state for later retrieval for validation.
     * Only "session" is supported by default.
     *
     * @param persistence The persistence mechanism
     */
    public void setPersistence(String persistence) {
        this.persistence = persistence;
    }

    @Override
    @Nonnull
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether state validation is enabled. Default ({@value #DEFAULT_ENABLED}).
     *
     * @param enabled The enabled flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
