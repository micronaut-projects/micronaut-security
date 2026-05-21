package io.micronaut.security.ldap.configuration;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static io.micronaut.security.testutils.ConfigurationSchemaUtils.assertDefaults;

class LdapConfigurationSchemaTest {
    @Test
    void generatedConfigurationSchemasContainDefaults() throws IOException {
        assertDefaults("io.micronaut.security.ldap.configuration.LdapConfiguration", Map.of(
            "enabled", true
        ));
        assertDefaults("io.micronaut.security.ldap.configuration.LdapConfiguration$ContextConfiguration", Map.of(
            "factory", "com.sun.jndi.ldap.LdapCtxFactory"
        ));
        assertDefaults("io.micronaut.security.ldap.configuration.LdapConfiguration$SearchConfiguration", Map.of(
            "subtree", true,
            "base", "",
            "filter", "(uid={0})"
        ));
        assertDefaults("io.micronaut.security.ldap.configuration.LdapConfiguration$GroupConfiguration", Map.of(
            "subtree", true,
            "base", "",
            "filter", "uniquemember={0}",
            "attribute", "cn",
            "enabled", false
        ));
    }
}
