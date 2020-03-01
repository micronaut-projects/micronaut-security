package io.micronaut.security.authentication;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.config.SecurityConfigurationProperties;

@ConfigurationProperties(BasicAuthAuthenticationConfiguration.PREFIX)
public class BasicAuthAuthenticationConfiguration implements Toggleable {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".basic-auth";

    private static final boolean DEFAULT_ENABLED = true;
    private static final String DEFAULT_ROLES_NAME = "roles";

    private boolean enabled = DEFAULT_ENABLED;
    private String rolesName = DEFAULT_ROLES_NAME;


    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Enables the {@link BasicAuthAuthenticationFetcher}. Default value {@value #DEFAULT_ENABLED}.
     *
     * @param enabled True if enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return The name in the {@link Authentication} that represents the roles
     */
    public String getRolesName() {
        return rolesName;
    }

    /**
     * @param rolesName The key to store the roles in the {@link Authentication} attributes
     */
    public void setRolesName(String rolesName) {
        this.rolesName = rolesName;
    }
}
