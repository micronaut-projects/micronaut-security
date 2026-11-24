package io.micronaut.security.ldap;

import io.micronaut.context.ApplicationContext;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code micronaut.security.ldap.*.context.properties} must reach JNDI with the exact key the user wrote.
 * JNDI environment names are dot-separated (and some are camelCase), so the map must be bound flat and
 * with raw keys instead of being split into nested maps or normalized to kebab-case.
 */
class LdapContextPropertiesBindingTest {

    @Test
    void contextPropertiesAreBoundFlatWithVerbatimKeys() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
                "micronaut.security.ldap.default.context.server", "ldap://localhost:1389",
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "test-fixture-not-a-secret",
                "micronaut.security.ldap.default.context.properties.java.naming.security.protocol", "ssl",
                "micronaut.security.ldap.default.context.properties.java.naming.ldap.derefAliases", "never",
                "micronaut.security.ldap.default.context.properties.com.sun.jndi.ldap.connect.timeout", "5000"
        ), "test")) {
            LdapConfiguration configuration = ctx.getBean(LdapConfiguration.class);
            Map<String, Object> expected = Map.of(
                    "java.naming.security.protocol", "ssl",
                    "java.naming.ldap.derefAliases", "never",
                    "com.sun.jndi.ldap.connect.timeout", "5000");

            assertEquals(expected, configuration.getContext().getProperties());
            assertEquals(expected, configuration.getManagerSettings().getAdditionalProperties());
            assertEquals(expected, configuration.getSettings("uid=riemann,dc=example,dc=com", "test-fixture-not-a-secret").getAdditionalProperties());
        }
    }
}
