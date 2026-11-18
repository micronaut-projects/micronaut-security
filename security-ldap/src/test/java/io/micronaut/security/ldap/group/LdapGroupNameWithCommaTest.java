package io.micronaut.security.ldap.group;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.LdapAuthenticationProvider;
import io.micronaut.security.ldap.LdapTestSupport;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

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
        server = LdapTestSupport.startServer("comma-group.ldif");
        context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of(
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", "ou=groups,dc=example,dc=com",
                "micronaut.security.ldap.default.groups.filter", "member={0}"
        )), "test");
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
        AuthenticationResponse response = authenticationProvider.authenticate(null, LdapTestSupport.request(username));
        assertTrue(response.isAuthenticated());
        Authentication authentication = response.getAuthentication().orElseThrow();
        assertEquals(username, authentication.getName());
        return authentication.getRoles();
    }
}
