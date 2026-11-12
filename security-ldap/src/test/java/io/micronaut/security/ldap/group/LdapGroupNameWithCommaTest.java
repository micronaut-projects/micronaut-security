package io.micronaut.security.ldap.group;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.LdapAuthenticationProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An LDAP group whose name contains a comma must be mapped to exactly one role,
 * never split into the roles of other groups.
 */
class LdapGroupNameWithCommaTest {

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;
    private static LdapAuthenticationProvider<Object, String, String> authenticationProvider;

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapGroupNameWithCommaTest.class.getClassLoader().getResourceAsStream("comma-group.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        context = ApplicationContext.run(Map.of(
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com",
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", "ou=groups,dc=example,dc=com",
                "micronaut.security.ldap.default.groups.filter", "member={0}"
        ), "test");
        authenticationProvider = context.getBean(LdapAuthenticationProvider.class);
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
    void groupNameContainingCommaIsASingleRole() {
        Collection<String> roles = authenticate("riemann");
        assertEquals(Set.of("club-chess,payroll-admins"), Set.copyOf(roles));
        assertFalse(roles.contains("payroll-admins"));
        assertFalse(roles.contains("club-chess"));
    }

    @Test
    void memberOfTheRealGroupStillGetsItsRole() {
        Collection<String> roles = authenticate("gauss");
        assertEquals(Set.of("payroll-admins"), Set.copyOf(roles));
    }

    private static Collection<String> authenticate(String username) {
        AuthenticationResponse response = authenticationProvider.authenticate(null, request(username));
        assertTrue(response.isAuthenticated());
        Authentication authentication = response.getAuthentication().orElseThrow();
        assertEquals(username, authentication.getName());
        return authentication.getRoles();
    }

    private static AuthenticationRequest<String, String> request(String username) {
        return new AuthenticationRequest<>() {
            @Override
            public String getIdentity() {
                return username;
            }

            @Override
            public String getSecret() {
                return "password";
            }
        };
    }
}
