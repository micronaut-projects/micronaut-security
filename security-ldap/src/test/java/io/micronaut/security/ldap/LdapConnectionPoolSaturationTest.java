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
import io.micronaut.security.ldap.context.ContextBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * With pooling enabled, a login whose pooled connection does not become available within
 * {@code pool.connect-timeout} fails instead of waiting indefinitely, and logins work again
 * once the held connections are released.
 * <p>
 * The JDK reads the pool bounds once per JVM, so the test does not assume {@code max-size} is in
 * effect: it holds manager contexts open until the pool refuses one, within a generous cap.
 */
class LdapConnectionPoolSaturationTest {

    private static final int CONNECT_TIMEOUT_MILLIS = 1000;
    private static final int CAP = 64;

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapConnectionPoolSaturationTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        context = ApplicationContext.run(Map.of(
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.context.pooled", true,
                "micronaut.security.ldap.default.context.pool.max-size", 2,
                "micronaut.security.ldap.default.context.pool.pref-size", 1,
                "micronaut.security.ldap.default.context.pool.connect-timeout", CONNECT_TIMEOUT_MILLIS + "ms",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ), "test");
    }

    @AfterAll
    static void cleanup() {
        if (context != null) {
            context.close();
        }
        if (server != null) {
            server.shutDown(true);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void loginFailsFastInsteadOfHangingWhenThePoolIsSaturated() {
        LdapConfiguration configuration = context.getBean(LdapConfiguration.class);
        ContextBuilder builder = context.getBean(ContextBuilder.class);
        LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);

        assertTrue(authenticate(provider, "riemann", "password").isAuthenticated(), "sanity check before saturating the pool");

        List<DirContext> held = new ArrayList<>();
        try {
            NamingException refused = null;
            long waited = 0;
            for (int i = 0; i < CAP && refused == null; i++) {
                long start = System.nanoTime();
                try {
                    held.add(builder.build(configuration.getManagerSettings()));
                } catch (NamingException e) {
                    refused = e;
                    waited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                }
            }
            assertNotNull(refused, () -> "the pool handed out " + held.size() + " connections and never saturated");
            assertInstanceOf(CommunicationException.class, refused);
            assertTrue(refused.getMessage().contains("Timeout exceeded while waiting for a connection"), refused.getMessage());
            assertTrue(waited >= CONNECT_TIMEOUT_MILLIS / 2, "waited only " + waited + "ms");
            assertTrue(waited < CONNECT_TIMEOUT_MILLIS * 10, "waited " + waited + "ms, the connect timeout did not bound the wait");

            // A login during the saturation fails within the timeout instead of hanging
            long start = System.nanoTime();
            AuthenticationResponse during = authenticate(provider, "riemann", "password");
            long loginWaited = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertFalse(during.isAuthenticated());
            assertEquals(AuthenticationFailureReason.UNKNOWN, assertInstanceOf(AuthenticationFailed.class, during).getReason());
            assertTrue(loginWaited < CONNECT_TIMEOUT_MILLIS * 10, "login waited " + loginWaited + "ms");
        } finally {
            for (DirContext dirContext : held) {
                builder.close(dirContext);
            }
        }

        // The held connections are released: logins work again
        AuthenticationResponse after = authenticate(provider, "riemann", "password");
        assertTrue(after.isAuthenticated(), () -> "login after releasing the pool failed with " + after);
        assertFalse(authenticate(provider, "riemann", "not-the-password").isAuthenticated());
    }

    private static AuthenticationResponse authenticate(LdapAuthenticationProvider<Object, String, String> provider, String username, String password) {
        return provider.authenticate(null, new AuthenticationRequest<>() {
            @Override
            public String getIdentity() {
                return username;
            }

            @Override
            public String getSecret() {
                return password;
            }
        });
    }
}
