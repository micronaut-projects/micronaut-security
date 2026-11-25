package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.LdapConnectionPoolConfigurer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The JNDI connection pool is off unless {@code micronaut.security.ldap.*.context.pooled} enables it,
 * and contexts bound with user credentials are never pooled.
 */
class LdapContextPooledConfigurationTest {

    private static InMemoryDirectoryServer server;

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapContextPooledConfigurationTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
    }

    @AfterAll
    static void cleanup() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    void managerContextIsNotPooledByDefault() {
        try (ApplicationContext context = ApplicationContext.run(properties(Map.of()), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertFalse(configuration.getContext().isPooled());
            assertFalse(configuration.getManagerSettings().getPooled());
            assertFalse(configuration.getSettings("uid=riemann,dc=example,dc=com", "password").getPooled());
        }
    }

    @Test
    void managerContextPoolingCanBeEnabled() {
        try (ApplicationContext context = ApplicationContext.run(properties(Map.of("micronaut.security.ldap.default.context.pooled", true)), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertTrue(configuration.getContext().isPooled());
            assertTrue(configuration.getManagerSettings().getPooled());
            assertFalse(configuration.getSettings("uid=riemann,dc=example,dc=com", "password").getPooled(), "user contexts must never be pooled");
        }
    }

    @Test
    void pooledManagerContextWaitsAtMostTheConnectTimeout() {
        String connectTimeout = LdapConnectionPoolConfigurer.CONNECT_TIMEOUT_PROPERTY;
        try (ApplicationContext context = ApplicationContext.run(properties(Map.of()), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertNull(configuration.getContext().getPool().getConnectTimeout());
            assertFalse(configuration.getManagerSettings().getAdditionalProperties().containsKey(connectTimeout), "an unpooled manager context keeps the JDK default");
        }
        try (ApplicationContext context = ApplicationContext.run(properties(Map.of("micronaut.security.ldap.default.context.pooled", true)), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertEquals("10000", configuration.getManagerSettings().getAdditionalProperties().get(connectTimeout), "10 seconds by default");
            assertFalse(configuration.getSettings("uid=riemann,dc=example,dc=com", "password").getAdditionalProperties().containsKey(connectTimeout), "user contexts are not pooled and keep the JDK default");

            configuration.getContext().setProperties(Map.of(connectTimeout, "250"));
            assertEquals("250", configuration.getManagerSettings().getAdditionalProperties().get(connectTimeout), "an explicit context property is kept");
        }
        try (ApplicationContext context = ApplicationContext.run(properties(Map.of(
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.connect-timeout", "2s")), "test")) {
            LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
            assertEquals(Duration.ofSeconds(2), configuration.getContext().getPool().getConnectTimeout());
            assertEquals("2000", configuration.getManagerSettings().getAdditionalProperties().get(connectTimeout));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void authenticationWorksWithAndWithoutPooling() {
        for (boolean pooled : new boolean[]{false, true}) {
            try (ApplicationContext context = ApplicationContext.run(properties(Map.of("micronaut.security.ldap.default.context.pooled", pooled)), "test")) {
                LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);

                AuthenticationResponse accepted = provider.authenticate(null, request("riemann", "password"));
                assertTrue(accepted.isAuthenticated(), "pooled=" + pooled);
                assertEquals("riemann", accepted.getAuthentication().orElseThrow().getName());

                AuthenticationResponse rejected = provider.authenticate(null, request("riemann", "not-the-password"));
                assertFalse(rejected.isAuthenticated(), "pooled=" + pooled);
                assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, rejected).getReason());
            }
        }
    }

    private static Map<String, Object> properties(Map<String, Object> extra) {
        Map<String, Object> properties = new HashMap<>(Map.of(
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ));
        properties.putAll(extra);
        return properties;
    }

    private static AuthenticationRequest<String, String> request(String username, String password) {
        return new AuthenticationRequest<>() {
            @Override
            public String getIdentity() {
                return username;
            }

            @Override
            public String getSecret() {
                return password;
            }
        };
    }
}
