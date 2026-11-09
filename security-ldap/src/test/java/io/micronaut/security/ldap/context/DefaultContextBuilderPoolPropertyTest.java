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

import io.micronaut.security.ldap.TestMaps;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DefaultContextBuilderPoolPropertyTest {

    private static final String POOL = "com.sun.jndi.ldap.connect.pool";

    @Test
    void poolKeyInAdditionalPropertiesIsIgnoredWhenNotPooled() throws Exception {
        assertNull(poolValue(false, TestMaps.of(POOL, "true")));
    }

    @Test
    void pooledContextBoundsThePoolWhenNothingIsConfigured() throws Exception {
        String[] properties = {
            LdapConnectionPoolConfigurer.MAX_SIZE_PROPERTY,
            LdapConnectionPoolConfigurer.PREF_SIZE_PROPERTY,
            LdapConnectionPoolConfigurer.IDLE_TIMEOUT_PROPERTY};
        Map<String, String> saved = new HashMap<>();
        for (String property : properties) {
            saved.put(property, System.clearProperty(property));
        }
        try {
            poolValue(false, TestMaps.of());
            for (String property : properties) {
                assertNull(System.getProperty(property), property + " must not be set for an unpooled context");
            }
            System.setProperty(LdapConnectionPoolConfigurer.MAX_SIZE_PROPERTY, "3");
            poolValue(true, TestMaps.of());
            assertEquals("3", System.getProperty(LdapConnectionPoolConfigurer.MAX_SIZE_PROPERTY), "an explicit bound is kept");
            assertEquals("5", System.getProperty(LdapConnectionPoolConfigurer.PREF_SIZE_PROPERTY));
            assertEquals("300000", System.getProperty(LdapConnectionPoolConfigurer.IDLE_TIMEOUT_PROPERTY));
        } finally {
            for (String property : properties) {
                String value = saved.get(property);
                if (value == null) {
                    System.clearProperty(property);
                } else {
                    System.setProperty(property, value);
                }
            }
        }
    }

    @Test
    void pooledContextWaitsAtMostTheConnectTimeoutForAConnection() throws Exception {
        String connectTimeout = LdapConnectionPoolConfigurer.CONNECT_TIMEOUT_PROPERTY;
        assertNull(environment(false, TestMaps.of()).get(connectTimeout), "an unpooled context keeps the JDK default");
        assertEquals("10000", environment(true, TestMaps.of()).get(connectTimeout), "a pooled context never waits indefinitely");
        assertEquals("250", environment(true, TestMaps.of(connectTimeout, "250")).get(connectTimeout), "an explicit value is kept");
    }

    @Test
    void bindKeysCannotBeOverriddenByAdditionalProperties() throws Exception {
        Hashtable<?, ?> env = environment(false, TestMaps.of(
            Context.SECURITY_AUTHENTICATION, "none",
            Context.SECURITY_PRINCIPAL, "cn=someone-else",
            Context.SECURITY_CREDENTIALS, "other",
            Context.PROVIDER_URL, "ldap://elsewhere:389",
            "java.naming.referral", "follow"));
        assertEquals("simple", env.get(Context.SECURITY_AUTHENTICATION), "an anonymous bind cannot be configured for a user context");
        assertEquals("cn=manager", env.get(Context.SECURITY_PRINCIPAL));
        assertEquals("secret", env.get(Context.SECURITY_CREDENTIALS));
        assertEquals("ldap://localhost:1", env.get(Context.PROVIDER_URL));
        assertEquals(CapturingFactory.class.getName(), env.get(Context.INITIAL_CONTEXT_FACTORY));
        assertEquals("follow", env.get("java.naming.referral"), "other properties still reach JNDI");
    }

    @Test
    void poolKeyIsSetOnlyByThePooledFlag() throws Exception {
        assertNull(poolValue(false, TestMaps.of()));
        assertEquals("true", poolValue(true, TestMaps.of()));
        assertEquals("true", poolValue(true, TestMaps.of(POOL, "false")));
    }

    private static Object poolValue(boolean pooled, Map<String, Object> additional) throws Exception {
        return environment(pooled, additional).get(POOL);
    }

    private static Hashtable<?, ?> environment(boolean pooled, Map<String, Object> additional) throws Exception {
        ContextSettings settings = new ContextSettings() {
            @Override
            public boolean getPooled() {
                return pooled;
            }

            @Override
            public String getFactory() {
                return CapturingFactory.class.getName();
            }

            @Override
            public String getUrl() {
                return "ldap://localhost:1";
            }

            @Override
            public String getDn() {
                return "cn=manager";
            }

            @Override
            public String getPassword() {
                return "secret";
            }

            @Override
            public Map<String, Object> getAdditionalProperties() {
                return additional;
            }
        };
        CapturingFactory.environment = null;
        NamingException e = assertThrows(NamingException.class, () -> new DefaultContextBuilder().build(settings));
        assertEquals(CapturingFactory.CAPTURED, e.getMessage());
        return CapturingFactory.environment;
    }

    /**
     * Captures the JNDI environment instead of connecting to a directory, then fails the context
     * creation so that no context has to be implemented.
     */
    public static class CapturingFactory implements InitialContextFactory {
        static final String CAPTURED = "environment captured";
        static volatile Hashtable<?, ?> environment;

        @Override
        public Context getInitialContext(Hashtable<?, ?> env) throws NamingException {
            environment = new Hashtable<>(env);
            throw new NamingException(CAPTURED);
        }
    }
}
