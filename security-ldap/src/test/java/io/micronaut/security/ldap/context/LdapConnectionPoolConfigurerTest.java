package io.micronaut.security.ldap.context;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static io.micronaut.security.ldap.context.LdapConnectionPoolConfigurer.IDLE_TIMEOUT_PROPERTY;
import static io.micronaut.security.ldap.context.LdapConnectionPoolConfigurer.MAX_SIZE_PROPERTY;
import static io.micronaut.security.ldap.context.LdapConnectionPoolConfigurer.PREF_SIZE_PROPERTY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Enabling {@code micronaut.security.ldap.*.context.pooled} must never leave the JNDI LDAP connection
 * pool unbounded: the pool bounds are applied as the JDK system properties before any pooled
 * connection is opened.
 */
class LdapConnectionPoolConfigurerTest {

    private static final String[] PROPERTIES = {MAX_SIZE_PROPERTY, PREF_SIZE_PROPERTY, IDLE_TIMEOUT_PROPERTY};

    private final Map<String, String> saved = new HashMap<>();

    @BeforeEach
    void clearPoolProperties() {
        for (String property : PROPERTIES) {
            saved.put(property, System.clearProperty(property));
        }
    }

    @AfterEach
    void restorePoolProperties() {
        for (String property : PROPERTIES) {
            String value = saved.get(property);
            if (value == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, value);
            }
        }
    }

    @Test
    void poolIsNotConfiguredWhenPoolingIsOff() {
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of()), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            LdapConfiguration.ContextConfiguration.PoolConfiguration pool = configuration.getContext().getPool();
            assertNull(pool.getMaxSize());
            assertNull(pool.getPrefSize());
            assertNull(pool.getIdleTimeout());
            for (String property : PROPERTIES) {
                assertNull(System.getProperty(property), property);
            }
        }
    }

    @Test
    void enablingPoolingBoundsThePoolByDefault() {
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of("micronaut.security.ldap.default.context.pooled", true)), "test")) {
            context.getBean(LdapConfiguration.class);
            assertEquals("20", System.getProperty(MAX_SIZE_PROPERTY));
            assertEquals("5", System.getProperty(PREF_SIZE_PROPERTY));
            assertEquals("300000", System.getProperty(IDLE_TIMEOUT_PROPERTY));
        }
    }

    @Test
    void poolBoundsAreConfigurable() {
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of(
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.max-size", 7,
                "micronaut.security.ldap.default.context.pool.pref-size", 2,
                "micronaut.security.ldap.default.context.pool.idle-timeout", "30s")), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            LdapConfiguration.ContextConfiguration.PoolConfiguration pool = configuration.getContext().getPool();
            assertEquals(7, pool.getMaxSize());
            assertEquals(2, pool.getPrefSize());
            assertEquals(Duration.ofSeconds(30), pool.getIdleTimeout());
            assertEquals("7", System.getProperty(MAX_SIZE_PROPERTY));
            assertEquals("2", System.getProperty(PREF_SIZE_PROPERTY));
            assertEquals("30000", System.getProperty(IDLE_TIMEOUT_PROPERTY));
        }
    }

    @Test
    void systemPropertySetOnTheCommandLineIsKeptWhenNotConfigured() {
        System.setProperty(MAX_SIZE_PROPERTY, "50");
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of("micronaut.security.ldap.default.context.pooled", true)), "test")) {
            context.getBean(LdapConfiguration.class);
            assertEquals("50", System.getProperty(MAX_SIZE_PROPERTY));
            assertEquals("5", System.getProperty(PREF_SIZE_PROPERTY));
            assertEquals("300000", System.getProperty(IDLE_TIMEOUT_PROPERTY));
        }
    }

    @Test
    void configuredValueReplacesSystemProperty() {
        System.setProperty(MAX_SIZE_PROPERTY, "50");
        System.setProperty(IDLE_TIMEOUT_PROPERTY, "0");
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of(
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.max-size", 7,
                "micronaut.security.ldap.default.context.pool.idle-timeout", "1m")), "test")) {
            context.getBean(LdapConfiguration.class);
            assertEquals("7", System.getProperty(MAX_SIZE_PROPERTY));
            assertEquals("5", System.getProperty(PREF_SIZE_PROPERTY));
            assertEquals("60000", System.getProperty(IDLE_TIMEOUT_PROPERTY));
        }
    }

    @Test
    void negativePoolValuesAreRejected() {
        for (Map.Entry<String, Object> negative : Map.<String, Object>of(
                "micronaut.security.ldap.default.context.pool.max-size", -1,
                "micronaut.security.ldap.default.context.pool.pref-size", -1,
                "micronaut.security.ldap.default.context.pool.idle-timeout", "-1s",
                "micronaut.security.ldap.default.context.pool.connect-timeout", "-5ms").entrySet()) {
            Map<String, Object> properties = ldap(Map.of("micronaut.security.ldap.default.context.pooled", true, negative.getKey(), negative.getValue()));
            try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
                RuntimeException e = assertThrows(RuntimeException.class, () -> context.getBean(LdapConfiguration.class), negative.getKey());
                assertTrue(rootMessage(e).contains("must not be negative") || rootMessage(e).contains("must be positive"), () -> negative.getKey() + ": " + rootMessage(e));
            }
            for (String property : PROPERTIES) {
                assertNull(System.getProperty(property), property + " must not be set when the configuration is rejected");
            }
        }
    }

    @Test
    void zeroConnectTimeoutIsRejectedBecauseTheJdkWouldWaitForever() {
        Map<String, Object> properties = ldap(Map.of(
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.connect-timeout", "0s"));
        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            RuntimeException e = assertThrows(RuntimeException.class, () -> context.getBean(LdapConfiguration.class));
            assertTrue(rootMessage(e).contains("connect-timeout must be positive"), () -> rootMessage(e));
        }
    }

    @Test
    void disabledConfigurationDoesNotTouchThePool() {
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of(
                "micronaut.security.ldap.default.enabled", false,
                "micronaut.security.ldap.default.context.pooled", true)), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertTrue(configuration.getContext().isPooled());
            for (String property : PROPERTIES) {
                assertNull(System.getProperty(property), property + " must not be set by a disabled configuration");
            }
        }
    }

    @Test
    void poolingCanBeExplicitlyUnbounded() {
        try (ApplicationContext context = ApplicationContext.run(ldap(Map.of(
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.max-size", 0)), "test")) {
            context.getBean(LdapConfiguration.class);
            assertEquals("0", System.getProperty(MAX_SIZE_PROPERTY));
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return String.valueOf(root.getMessage());
    }

    private static Map<String, Object> ldap(Map<String, Object> extra) {
        Map<String, Object> properties = new HashMap<>(Map.of(
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:1",
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ));
        properties.putAll(extra);
        return properties;
    }
}
