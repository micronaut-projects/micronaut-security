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
package io.micronaut.security.ldap.configuration;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.EachProperty;
import io.micronaut.context.annotation.Parameter;
import io.micronaut.core.convert.format.MapFormat;
import io.micronaut.core.naming.conventions.StringConvention;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.annotation.Nullable;
import io.micronaut.core.util.Toggleable;
import io.micronaut.security.config.SecurityConfigurationProperties;
import io.micronaut.security.ldap.context.ContextConfigurationContextSettings;
import io.micronaut.security.ldap.context.ContextSettings;
import io.micronaut.security.ldap.context.SearchSettings;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration for LDAP authentication.
 * <p>
 * A configuration is created for every name under {@value #PREFIX} that has nested properties. Single-valued keys
 * directly under the prefix, such as the global switch {@code micronaut.security.ldap.enabled}, are not
 * configuration names.
 *
 * @author James Kleeh
 * @since 1.0
 */
@EachProperty(value = LdapConfiguration.PREFIX, primary = "default")
@Requires(condition = LdapConfigurationCondition.class)
public class LdapConfiguration implements Toggleable {

    public static final String PREFIX = SecurityConfigurationProperties.PREFIX + ".ldap";

    /**
     * The default enable value.
     */
    @SuppressWarnings("WeakerAccess")
    public static final boolean DEFAULT_ENABLED = true;

    private boolean enabled = DEFAULT_ENABLED;
    private ContextConfiguration context = new ContextConfiguration();
    private SearchConfiguration search = new SearchConfiguration();
    private GroupConfiguration group = new GroupConfiguration();
    private final String name;

    /**
     * @param name The name of the configuration
     */
    LdapConfiguration(@Parameter String name) {
        this.name = name;
    }

    /**
     * @return The name of the configuration
     */
    public String getName() {
        return name;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether this configuration is enabled. Default {@value #DEFAULT_ENABLED}.
     *
     * @param enabled The enabled setting
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return The context configuration
     */
    public ContextConfiguration getContext() {
        return context;
    }

    /**
     * Sets the context configuration.
     *
     * @param contextConfiguration The context configuration
     */
    public void setContext(ContextConfiguration contextConfiguration) {
        this.context = contextConfiguration;
    }

    /**
     * @return The search configuration
     */
    public SearchConfiguration getSearch() {
        return search;
    }

    /**
     * Sets the search configuration.
     *
     * @param searchConfiguration The search configuration
     */
    public void setSearch(SearchConfiguration searchConfiguration) {
        this.search = searchConfiguration;
    }

    /**
     * @return The group configuration
     */
    public GroupConfiguration getGroups() {
        return group;
    }

    /**
     * Sets the group configuration.
     *
     * @param groupConfiguration The group configuration
     */
    public void setGroups(GroupConfiguration groupConfiguration) {
        this.group = groupConfiguration;
    }

    /**
     * Returns settings for creating a context for a given dn and password.
     *
     * @param dn       The user dn to bind with
     * @param password The user password to bind with
     * @return Settings to use to create a context
     */
    public ContextSettings getSettings(String dn, String password) {
        return new ContextConfigurationContextSettings(this, dn, password);
    }

    /**
     * @return Settings for creating a context for the manager.
     */
    public ContextSettings getManagerSettings() {
        return new ContextConfigurationContextSettings(this);
    }

    /**
     * The context configuration.
     */
    @ConfigurationProperties("context")
    public static class ContextConfiguration {

        /**
         * The configuration prefix.
         */
        public static final String PREFIX = LdapConfiguration.PREFIX + ".context";

        /**
         * The default pooled value.
         */
        @SuppressWarnings("WeakerAccess")
        public static final boolean DEFAULT_POOLED = false;

        private static final String DEFAULT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

        private String server;
        private String managerDn;
        private String managerPassword;
        private String factory = DEFAULT_FACTORY;
        private boolean pooled = DEFAULT_POOLED;
        private PoolConfiguration pool = new PoolConfiguration();
        private Map<String, Object> properties = Collections.emptyMap();

        /**
         * @return The ldap server URL
         */
        public String getServer() {
            return server;
        }

        /**
         * Sets the server URL.
         *
         * @param server The server URL
         */
        public void setServer(String server) {
            this.server = server;
        }

        /**
         * @return The manager DN
         */
        public String getManagerDn() {
            return managerDn;
        }

        /**
         * Sets the manager DN.
         *
         * @param managerDn The manager DN
         */
        public void setManagerDn(String managerDn) {
            this.managerDn = managerDn;
        }

        /**
         * @return The manager password
         */
        public String getManagerPassword() {
            return managerPassword;
        }

        /**
         * Sets the manager password.
         *
         * @param managerPassword The manager password
         */
        public void setManagerPassword(String managerPassword) {
            this.managerPassword = managerPassword;
        }

        /**
         * @return The context factory class
         */
        public String getFactory() {
            return factory;
        }

        /**
         * Sets the context factory class. Default {@value #DEFAULT_FACTORY}
         *
         * @param factory The factory class
         */
        public void setFactory(String factory) {
            this.factory = factory;
        }

        /**
         * @return Whether the manager context uses the JNDI LDAP connection pool
         * @since 5.5.2
         */
        public boolean isPooled() {
            return pooled;
        }

        /**
         * Sets whether the manager context uses the JNDI LDAP connection pool
         * ({@code com.sun.jndi.ldap.connect.pool}). The pool is shared by the whole JVM and, unless bounded,
         * the JDK neither limits its size nor closes idle connections, so a burst of authentication attempts
         * can leave the directory without free connections for user binds. When pooling is enabled, the pool
         * is bounded with {@link #getPool()}, whose values are applied as the
         * {@code com.sun.jndi.ldap.connect.pool.maxsize}, {@code com.sun.jndi.ldap.connect.pool.prefsize} and
         * {@code com.sun.jndi.ldap.connect.pool.timeout} system properties before the first pooled connection
         * is opened. Contexts bound with user credentials are never pooled. This is the only supported pooling
         * switch: a {@code com.sun.jndi.ldap.connect.pool} entry in the additional context properties is ignored.
         * Default {@value #DEFAULT_POOLED}.
         *
         * @param pooled Whether the manager context is pooled
         * @since 5.5.2
         */
        public void setPooled(boolean pooled) {
            this.pooled = pooled;
        }

        /**
         * @return The bounds of the JNDI LDAP connection pool, applied when {@link #isPooled()} is {@code true}
         * @since 5.5.2
         */
        public PoolConfiguration getPool() {
            return pool;
        }

        /**
         * Sets the bounds of the JNDI LDAP connection pool, applied when {@link #isPooled()} is {@code true}.
         *
         * @param pool The pool configuration
         * @since 5.5.2
         */
        public void setPool(PoolConfiguration pool) {
            this.pool = pool;
        }

        /**
         * @return Any additional properties
         */
        public Map<String, Object> getProperties() {
            return properties;
        }

        /**
         * Any additional properties that should be passed to {@link javax.naming.directory.InitialDirContext#InitialDirContext(java.util.Hashtable)}.
         * Keys are bound verbatim and flat, so a key such as {@code java.naming.security.protocol} is passed to JNDI
         * as a single property name instead of being split into nested maps.
         *
         * @param properties The additional properties
         */
        public void setProperties(@MapFormat(transformation = MapFormat.MapTransformation.FLAT, keyFormat = StringConvention.RAW) Map<String, Object> properties) {
            this.properties = properties;
        }

        /**
         * Bounds of the JNDI LDAP connection pool, applied when {@link ContextConfiguration#isPooled()} is
         * {@code true}. The pool is shared by the whole JVM: the values are applied as the
         * {@code com.sun.jndi.ldap.connect.pool.maxsize}, {@code com.sun.jndi.ldap.connect.pool.prefsize} and
         * {@code com.sun.jndi.ldap.connect.pool.timeout} system properties when the configuration is created.
         * A value set here always wins. A value not set here keeps the system property if it is already set,
         * for example on the command line, and otherwise falls back to the default. {@link #getConnectTimeout()}
         * is applied to the pooled manager context itself, as the {@code com.sun.jndi.ldap.connect.timeout}
         * JNDI environment property, and bounds the wait for a connection when the pool is saturated.
         * <p>
         * The JDK reads these system properties once, when the first pooled JNDI LDAP connection of the JVM is
         * opened. Values applied after that have no effect.
         *
         * @since 5.5.2
         */
        @ConfigurationProperties("pool")
        public static class PoolConfiguration {

            /**
             * The configuration prefix.
             */
            public static final String PREFIX = ContextConfiguration.PREFIX + ".pool";

            /**
             * The default maximum number of pooled connections per connection identity.
             */
            public static final int DEFAULT_MAX_SIZE = 20;

            /**
             * The default preferred number of pooled connections per connection identity.
             */
            public static final int DEFAULT_PREF_SIZE = 5;

            /**
             * The default time after which an idle pooled connection is closed.
             */
            public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofMinutes(5);

            /**
             * The default time a login waits for a pooled connection when the pool is saturated.
             */
            public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);

            private @Nullable Integer maxSize;
            private @Nullable Integer prefSize;
            private @Nullable Duration idleTimeout;
            private @Nullable Duration connectTimeout;

            /**
             * @return The maximum number of pooled connections per connection identity, or null to keep the
             * {@code com.sun.jndi.ldap.connect.pool.maxsize} system property if set and otherwise use {@value #DEFAULT_MAX_SIZE}
             */
            public @Nullable Integer getMaxSize() {
                return maxSize;
            }

            /**
             * Sets the maximum number of connections the pool keeps per connection identity (server, manager DN and
             * password). Once reached, a login waits for a pooled connection to be released instead of opening a new
             * one. {@code 0} removes the bound, which lets a burst of login attempts exhaust the connections of the
             * directory; a negative value is rejected. Default {@value #DEFAULT_MAX_SIZE}, unless the
             * {@code com.sun.jndi.ldap.connect.pool.maxsize} system property is already set.
             *
             * @param maxSize The maximum pool size
             */
            public void setMaxSize(@Nullable Integer maxSize) {
                this.maxSize = requireNonNegative("max-size", maxSize);
            }

            /**
             * @return The preferred number of pooled connections per connection identity, or null to keep the
             * {@code com.sun.jndi.ldap.connect.pool.prefsize} system property if set and otherwise use {@value #DEFAULT_PREF_SIZE}
             */
            public @Nullable Integer getPrefSize() {
                return prefSize;
            }

            /**
             * Sets the preferred number of connections the pool keeps per connection identity. Connections released
             * above this number are closed rather than returned to the pool. A negative value is rejected.
             * Default {@value #DEFAULT_PREF_SIZE}, unless the {@code com.sun.jndi.ldap.connect.pool.prefsize} system
             * property is already set.
             *
             * @param prefSize The preferred pool size
             */
            public void setPrefSize(@Nullable Integer prefSize) {
                this.prefSize = requireNonNegative("pref-size", prefSize);
            }

            /**
             * @return The time after which an idle pooled connection is closed, or null to keep the
             * {@code com.sun.jndi.ldap.connect.pool.timeout} system property if set and otherwise use 5 minutes
             */
            public @Nullable Duration getIdleTimeout() {
                return idleTimeout;
            }

            /**
             * Sets the time after which an idle pooled connection is closed. {@code 0} keeps idle connections open
             * forever; a negative value is rejected. Default 5 minutes, unless the
             * {@code com.sun.jndi.ldap.connect.pool.timeout} system property is already set.
             *
             * @param idleTimeout The idle timeout
             */
            public void setIdleTimeout(@Nullable Duration idleTimeout) {
                this.idleTimeout = requireNonNegative("idle-timeout", idleTimeout);
            }

            /**
             * @return The time a login waits for a pooled connection when the pool is saturated, or null for 10 seconds;
             * always positive
             */
            public @Nullable Duration getConnectTimeout() {
                return connectTimeout;
            }

            /**
             * Sets the time a login waits for a pooled connection to be released when the pool already holds
             * {@code max-size} connections, and the time allowed to open a new pooled connection. Without it, the
             * JDK waits indefinitely, so a hung directory operation holding every pooled connection would block
             * every later login. Applied as the {@code com.sun.jndi.ldap.connect.timeout} JNDI environment property of
             * the pooled manager context, unless {@link ContextConfiguration#getProperties()} already sets that key.
             * The JDK waits indefinitely for a value of {@code 0} or less, so such a value is rejected. Default 10 seconds.
             *
             * @param connectTimeout The connect timeout
             */
            public void setConnectTimeout(@Nullable Duration connectTimeout) {
                if (connectTimeout != null && (connectTimeout.isNegative() || connectTimeout.isZero())) {
                    throw new IllegalArgumentException(PREFIX + ".connect-timeout must be positive: " + connectTimeout);
                }
                this.connectTimeout = connectTimeout;
            }

            private static @Nullable Integer requireNonNegative(String name, @Nullable Integer value) {
                if (value != null && value < 0) {
                    throw new IllegalArgumentException(PREFIX + "." + name + " must not be negative: " + value);
                }
                return value;
            }

            private static @Nullable Duration requireNonNegative(String name, @Nullable Duration value) {
                if (value != null && value.isNegative()) {
                    throw new IllegalArgumentException(PREFIX + "." + name + " must not be negative: " + value);
                }
                return value;
            }
        }
    }

    /**
     * The user search configuration.
     */
    @ConfigurationProperties("search")
    public static class SearchConfiguration {

        /**
         * The configuration prefix.
         */
        public static final String PREFIX = LdapConfiguration.PREFIX + ".search";

        private static final boolean DEFAULT_SUBTREE = true;
        private static final String DEFAULT_FILTER = "(uid={0})";

        private boolean subtree = DEFAULT_SUBTREE;
        private String base = "";
        private String filter = DEFAULT_FILTER;
        private String[] attributes = null;
        private @Nullable String decoyDn;

        /**
         * @return The DN of the decoy entry bound when a username matches no entry, or null for a random non-existent entry
         * @since 4.18.2
         */
        public @Nullable String getDecoyDn() {
            return decoyDn;
        }

        /**
         * Sets the DN bound, with the supplied password, when a username matches no directory entry, so that an unknown
         * username costs the application the same bind round trip as a wrong password. Defaults to a random non-existent
         * entry under the search base, which equalises only the client-side cost. Point it at a real account with an
         * unmatchable password, excluded from any lockout policy, to also equalise directory-side work (password hashing,
         * bad-password counters).
         *
         * @param decoyDn The decoy DN
         * @since 4.18.2
         */
        public void setDecoyDn(@Nullable String decoyDn) {
            this.decoyDn = decoyDn;
        }

        /**
         * @return True if the subtree should be searched
         */
        public boolean isSubtree() {
            return subtree;
        }

        /**
         * Sets if the subtree should be searched. Default {@value #DEFAULT_SUBTREE}
         *
         * @param subtree The subtree
         */
        public void setSubtree(boolean subtree) {
            this.subtree = subtree;
        }

        /**
         * @return The base DN to search from
         */
        public String getBase() {
            return base;
        }

        /**
         * Sets the base DN to search.
         *
         * @param base The base DN
         */
        public void setBase(String base) {
            this.base = base;
        }

        /**
         * @return The search filter
         */
        public String getFilter() {
            return filter;
        }

        /**
         * Sets the search filter. Default {@value #DEFAULT_FILTER}
         *
         * @param filter The search filter
         */
        public void setFilter(String filter) {
            this.filter = filter;
        }

        /**
         * @return The attributes to return. Null if all
         */
        public String[] getAttributes() {
            return attributes;
        }

        /**
         * Sets the attributes to return. Default all
         *
         * @param attributes The attributes
         */
        public void setAttributes(String[] attributes) {
            this.attributes = attributes;
        }

        /**
         * @param arguments The search arguments
         * @return The settings to search for a user
         */
        public SearchSettings getSettings(Object[] arguments) {
            return new SearchPropertiesSearchSettings(this, arguments);
        }
    }

    /**
     * The group configuration.
     */
    @ConfigurationProperties("groups")
    public static class GroupConfiguration implements Toggleable {

        public static final String PREFIX = LdapConfiguration.PREFIX + ".groups";

        /**
         * The default enable value.
         */
        @SuppressWarnings("WeakerAccess")
        public static final boolean DEFAULT_ENABLED = false;

        private static final boolean DEFAULT_SUBTREE = true;
        private static final String DEFAULT_FILTER = "uniquemember={0}";
        private static final String DEFAULT_ATTR = "cn";

        private boolean enabled = DEFAULT_ENABLED;
        private boolean subtree = DEFAULT_SUBTREE;
        private String base = "";
        private String filter = DEFAULT_FILTER;
        private String filterAttribute;
        private String attribute = DEFAULT_ATTR;

        /**
         * @return True if the subtree should be searched
         */
        public boolean isSubtree() {
            return subtree;
        }

        /**
         * Sets if the subtree should be searched. Default {@value #DEFAULT_SUBTREE}
         *
         * @param subtree The subtree
         */
        public void setSubtree(boolean subtree) {
            this.subtree = subtree;
        }

        /**
         * @return The base DN to search from
         */
        public String getBase() {
            return base;
        }

        /**
         * Sets the base DN to search from.
         *
         * @param base The base DN
         */
        public void setBase(String base) {
            this.base = base;
        }

        /**
         * @return The filter used to search for groups
         */
        public String getFilter() {
            return filter;
        }

        /**
         * Sets the group search filter. Default {@value #DEFAULT_FILTER}
         *
         * @param filter The filter
         */
        public void setFilter(String filter) {
            this.filter = filter;
        }

        /**
         * @return Which attribute is the group name
         */
        public String getAttribute() {
            return attribute;
        }

        /**
         * Sets the group attribute name. Default {@value #DEFAULT_ATTR}
         *
         * @param attribute The attribute name
         */
        public void setAttribute(String attribute) {
            this.attribute = attribute;
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets if group search is enabled. Default {@value #DEFAULT_ENABLED}
         *
         * @param enabled The enabled setting
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * @param arguments The search arguments
         * @return Settings to search ldap groups
         */
        public SearchSettings getSearchSettings(Object[] arguments) {
            return new GroupPropertiesSearchSettings(this, arguments);
        }

        /**
         * The argument to pass to the search filter.
         *
         * @return The name of an attribute in the user
         */
        public Optional<String> getFilterAttribute() {
            return Optional.ofNullable(filterAttribute);
        }

        /**
         * Sets the name of the user attribute to bind to the
         * group search filter. Defaults to the user's DN.
         *
         * @param filterAttribute The attribute
         */
        public void setFilterAttribute(String filterAttribute) {
            this.filterAttribute = filterAttribute;
        }
    }
}
