/*
 * Copyright 2017-2023 original authors
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
package io.micronaut.security.ldap.context;

import io.micronaut.security.ldap.configuration.LdapConfiguration;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of {@link ContextSettings} that derives its values from
 * an instance of {@link LdapConfiguration}.
 *
 * @author James Kleeh
 * @since 1.0
 */
public class ContextConfigurationContextSettings implements ContextSettings {

    private final LdapConfiguration.ContextConfiguration contextConfiguration;
    private final String dn;
    private final String password;
    private final boolean pooled;

    /**
     * Settings for the manager context. The context is pooled only if
     * {@link LdapConfiguration.ContextConfiguration#isPooled()} is {@code true}.
     *
     * @param configuration The ldap configuration
     */
    public ContextConfigurationContextSettings(LdapConfiguration configuration) {
        this.contextConfiguration = configuration.getContext();
        this.dn = contextConfiguration.getManagerDn();
        this.password = contextConfiguration.getManagerPassword();
        this.pooled = contextConfiguration.isPooled();
    }

    /**
     * Settings for a context bound with user credentials. Such a context is never pooled.
     *
     * @param configuration The ldap configuration
     * @param dn            The user DN to bind with
     * @param password      The password to bind with
     */
    public ContextConfigurationContextSettings(LdapConfiguration configuration,
                                               String dn, String password) {
        this.contextConfiguration = configuration.getContext();
        this.dn = dn;
        this.password = password;
        this.pooled = false;
    }

    @Override
    public boolean getPooled() {
        return pooled;
    }

    @Override
    public String getFactory() {
        return contextConfiguration.getFactory();
    }

    @Override
    public String getUrl() {
        return contextConfiguration.getServer();
    }

    @Override
    public String getDn() {
        return dn;
    }

    @Override
    public String getPassword() {
        return password;
    }

    /**
     * The additional properties of the configuration. For the pooled manager context they also carry the
     * {@code com.sun.jndi.ldap.connect.timeout} JNDI environment property derived from
     * {@link LdapConfiguration.ContextConfiguration.PoolConfiguration#getConnectTimeout()}, unless the
     * configured properties already set it, so that a login does not wait indefinitely when the pool is saturated.
     *
     * @return The additional properties
     */
    @Override
    public Map<String, Object> getAdditionalProperties() {
        Map<String, Object> properties = contextConfiguration.getProperties();
        if (!pooled || properties.containsKey(LdapConnectionPoolConfigurer.CONNECT_TIMEOUT_PROPERTY)) {
            return properties;
        }
        Map<String, Object> withConnectTimeout = new HashMap<>(properties);
        LdapConnectionPoolConfigurer.applyConnectTimeout(withConnectTimeout, contextConfiguration.getPool().getConnectTimeout());
        return withConnectTimeout;
    }
}
