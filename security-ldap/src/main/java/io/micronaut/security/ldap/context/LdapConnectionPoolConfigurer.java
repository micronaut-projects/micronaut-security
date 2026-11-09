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
package io.micronaut.security.ldap.context;

import io.micronaut.context.event.BeanCreatedEvent;
import io.micronaut.context.event.BeanCreatedEventListener;
import io.micronaut.core.annotation.Internal;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.Map;
import io.micronaut.core.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bounds the JNDI LDAP connection pool for every {@link LdapConfiguration} whose manager context is pooled.
 * <p>
 * The JDK configures its pool with system properties only, read once when the first pooled connection of
 * the JVM is opened, and leaves the pool unbounded by default. This listener runs when an
 * {@link LdapConfiguration} bean is created, which precedes the creation of its
 * {@link io.micronaut.security.ldap.LdapAuthenticationProvider} and therefore the first pooled connection
 * Micronaut Security opens, and, for an enabled configuration, applies {@link LdapConfiguration.ContextConfiguration.PoolConfiguration}
 * as the {@code com.sun.jndi.ldap.connect.pool.maxsize}, {@code com.sun.jndi.ldap.connect.pool.prefsize}
 * and {@code com.sun.jndi.ldap.connect.pool.timeout} system properties. A configured value always wins; a
 * value that is not configured keeps a system property that is already set and otherwise falls back to the
 * default.
 *
 * @author Sergio del Amo
 * @since 4.18.2
 */
@Internal
@Singleton
public final class LdapConnectionPoolConfigurer implements BeanCreatedEventListener<LdapConfiguration> {

    /**
     * System property holding the maximum number of pooled connections per connection identity.
     */
    public static final String MAX_SIZE_PROPERTY = "com.sun.jndi.ldap.connect.pool.maxsize";

    /**
     * System property holding the preferred number of pooled connections per connection identity.
     */
    public static final String PREF_SIZE_PROPERTY = "com.sun.jndi.ldap.connect.pool.prefsize";

    /**
     * System property holding the milliseconds after which an idle pooled connection is closed.
     */
    public static final String IDLE_TIMEOUT_PROPERTY = "com.sun.jndi.ldap.connect.pool.timeout";

    /**
     * JNDI environment property, set on the pooled context itself, holding the milliseconds a context waits for a
     * pooled connection when the pool is saturated and the time allowed to open a new connection. Without it the
     * JDK waits indefinitely.
     */
    public static final String CONNECT_TIMEOUT_PROPERTY = "com.sun.jndi.ldap.connect.timeout";

    private static final Logger LOG = LoggerFactory.getLogger(LdapConnectionPoolConfigurer.class);

    /**
     * Applies the default bound to every pool system property that is not set. {@link DefaultContextBuilder}
     * calls this before opening a pooled context, so that a pooled context built outside an
     * {@link LdapConfiguration}, through {@link ContextBuilder#build(String, String, String, String, boolean)},
     * never uses an unbounded pool either. Properties that are already set, by this listener or on the
     * command line, are left untouched.
     */
    public static void applyDefaults() {
        setIfAbsent(MAX_SIZE_PROPERTY, LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_MAX_SIZE);
        setIfAbsent(PREF_SIZE_PROPERTY, LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_PREF_SIZE);
        setIfAbsent(IDLE_TIMEOUT_PROPERTY, LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_IDLE_TIMEOUT.toMillis());
    }

    /**
     * Adds the connect timeout of a pooled context to its JNDI environment, unless the environment already sets it.
     *
     * @param environment    The JNDI environment of a pooled context
     * @param connectTimeout The configured connect timeout, or null for the default
     */
    public static void applyConnectTimeout(Map<? super String, ? super String> environment, @Nullable Duration connectTimeout) {
        if (!environment.containsKey(CONNECT_TIMEOUT_PROPERTY)) {
            Duration timeout = connectTimeout != null ? connectTimeout : LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_CONNECT_TIMEOUT;
            environment.put(CONNECT_TIMEOUT_PROPERTY, Long.toString(timeout.toMillis()));
        }
    }

    private static void setIfAbsent(String property, long defaultValue) {
        if (System.getProperty(property) == null) {
            System.setProperty(property, Long.toString(defaultValue));
        }
    }

    @Override
    public LdapConfiguration onCreated(BeanCreatedEvent<LdapConfiguration> event) {
        LdapConfiguration configuration = event.getBean();
        LdapConfiguration.ContextConfiguration context = configuration.getContext();
        if (configuration.isEnabled() && context.isPooled()) {
            LdapConfiguration.ContextConfiguration.PoolConfiguration pool = context.getPool();
            String name = configuration.getName();
            Duration idleTimeout = pool.getIdleTimeout();
            long maxSize = apply(MAX_SIZE_PROPERTY, pool.getMaxSize(), LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_MAX_SIZE, name);
            apply(PREF_SIZE_PROPERTY, pool.getPrefSize(), LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_PREF_SIZE, name);
            long timeout = apply(IDLE_TIMEOUT_PROPERTY, idleTimeout == null ? null : idleTimeout.toMillis(), LdapConfiguration.ContextConfiguration.PoolConfiguration.DEFAULT_IDLE_TIMEOUT.toMillis(), name);
            if (LOG.isWarnEnabled()) {
                if (maxSize == 0) {
                    LOG.warn("The JNDI LDAP connection pool used by LDAP configuration [{}] is unbounded ({} is 0): a burst of login attempts can exhaust the connections of the directory", name, MAX_SIZE_PROPERTY);
                } else if (maxSize < 0) {
                    LOG.warn("The JNDI LDAP connection pool used by LDAP configuration [{}] never creates a connection ({} is {}): every manager bind will time out", name, MAX_SIZE_PROPERTY, maxSize);
                }
                if (timeout <= 0) {
                    LOG.warn("The JNDI LDAP connection pool used by LDAP configuration [{}] never closes idle connections ({} is {})", name, IDLE_TIMEOUT_PROPERTY, timeout);
                }
            }
        }
        return configuration;
    }

    /**
     * Applies one pool bound as a system property.
     *
     * @param property     The system property
     * @param configured   The configured value, or null if not configured
     * @param defaultValue The default applied when nothing is configured and the system property is not set
     * @param name         The name of the LDAP configuration, for logging
     * @return The value of the system property after this call, or {@code -1} if it is not a number
     */
    private static long apply(String property, @Nullable Number configured, long defaultValue, String name) {
        // Negative configured values are rejected by PoolConfiguration; a negative system property set on the
        // command line is applied as is and reported by the caller.
        String current = System.getProperty(property);
        if (configured != null) {
            String value = Long.toString(configured.longValue());
            if (current != null && !current.equals(value) && LOG.isWarnEnabled()) {
                LOG.warn("LDAP configuration [{}] sets the JVM-wide system property [{}] to [{}], replacing [{}]", name, property, value, current);
            }
            System.setProperty(property, value);
        } else {
            setIfAbsent(property, defaultValue);
        }
        String effective = System.getProperty(property);
        if (LOG.isDebugEnabled()) {
            LOG.debug("LDAP configuration [{}] pools the manager context with [{}] = [{}]", name, property, effective);
        }
        try {
            return Long.parseLong(effective);
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
