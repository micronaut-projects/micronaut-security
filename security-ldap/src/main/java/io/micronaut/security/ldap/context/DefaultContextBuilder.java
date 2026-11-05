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

import jakarta.inject.Singleton;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default implementation of {@link ContextBuilder}.
 *
 * @author James Kleeh
 * @since 1.0
 */
@Singleton
public class DefaultContextBuilder implements ContextBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultContextBuilder.class);

    private static final String CONNECT_POOL = "com.sun.jndi.ldap.connect.pool";

    /**
     * Keys controlling the bind itself. They are always set by the builder and ignored in additional properties.
     */
    private static final Set<String> RESERVED_KEYS = Set.of(
            Context.INITIAL_CONTEXT_FACTORY,
            Context.PROVIDER_URL,
            Context.SECURITY_AUTHENTICATION,
            Context.SECURITY_PRINCIPAL,
            Context.SECURITY_CREDENTIALS,
            CONNECT_POOL);

    /**
     * Reserved keys found in additional properties which have already been reported at WARN level.
     */
    private final Set<String> warnedReservedKeys = ConcurrentHashMap.newKeySet();

    @Override
    public DirContext build(ContextSettings contextSettings) throws NamingException {
        return build(contextSettings.getFactory(),
                contextSettings.getUrl(),
                contextSettings.getDn(),
                contextSettings.getPassword(),
                contextSettings.getPooled(),
                contextSettings.getAdditionalProperties());
    }

    @Override
    public DirContext build(String factory, String server, String user, String password, boolean pooled) throws NamingException {
        return build(factory, server, user, password, pooled, Collections.emptyMap());
    }

    private DirContext build(String factory, String server, String user, String password, boolean pooled, Map<String, Object> additionalProperties) throws NamingException {
        Properties props = new Properties();
        // Additional properties go first and never contain the reserved keys, so that the keys controlling the
        // bind itself always win: configuration cannot change the factory, the server, the credentials, the
        // authentication mechanism or the pooling of a context bound with user credentials.
        for (Map.Entry<String, Object> entry : additionalProperties.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (RESERVED_KEYS.contains(key)) {
                warnReservedKey(key);
            } else if (value != null) {
                props.put(key, toJndiValue(value));
            }
        }
        props.put(Context.INITIAL_CONTEXT_FACTORY, factory);
        props.put(Context.PROVIDER_URL, server);
        props.put(Context.SECURITY_AUTHENTICATION, "simple");
        props.put(Context.SECURITY_PRINCIPAL, user);
        props.put(Context.SECURITY_CREDENTIALS, password);
        // Pooling is controlled only by the "pooled" flag
        if (pooled) {
            // The JDK pool is unbounded unless its system properties say otherwise, and a context waits
            // indefinitely for a pooled connection unless its environment bounds the wait
            LdapConnectionPoolConfigurer.applyDefaults();
            LdapConnectionPoolConfigurer.applyConnectTimeout(props, null);
            props.put(CONNECT_POOL, "true");
        }
        try {
            return new InitialDirContext(props);
        } catch (RuntimeException e) {
            // The JDK LDAP provider throws unchecked exceptions for environment entries it cannot use, for example a
            // String for a key which takes an object. Report it as a NamingException so that callers treat it as a
            // failed bind instead of an unexpected error.
            NamingException namingException = new NamingException("Could not create the LDAP context: " + e.getMessage());
            namingException.setRootCause(e);
            throw namingException;
        }
    }

    /**
     * Reports a reserved key found in the additional properties. A misconfiguration is static, so each key is
     * reported at WARN level once per builder and at DEBUG level afterwards.
     *
     * @param key The reserved key
     */
    private void warnReservedKey(String key) {
        if (warnedReservedKeys.add(key)) {
            LOG.warn("Ignoring LDAP context property '{}': it is managed by Micronaut Security and cannot be overridden through context.properties", key);
        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Ignoring LDAP context property '{}': it is managed by Micronaut Security and cannot be overridden through context.properties", key);
        }
    }

    /**
     * The LDAP provider of the JDK reads its environment entries as {@link String}, so a scalar bound from
     * configuration (for example {@code com.sun.jndi.ldap.connect.timeout: 5000}, which YAML binds as an
     * {@link Integer}) is converted to its string form. Any other object is passed through unchanged, since
     * some entries are objects by contract, such as {@code java.naming.ldap.control.connect}.
     *
     * @param value The configured value
     * @return The value to put in the JNDI environment
     */
    private static Object toJndiValue(Object value) {
        if (value instanceof CharSequence || value instanceof Number || value instanceof Boolean || value instanceof Character) {
            return value.toString();
        }
        return value;
    }

    @Override
    public void close(DirContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Exception occurred while closing an LDAP context", e);
                }
            }
        }
    }
}
