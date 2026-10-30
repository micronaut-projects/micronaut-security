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
import reactor.core.publisher.Mono;

import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

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
    private static LdapAuthenticationProvider authenticationProvider;

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapGroupNameWithCommaTest.class.getClassLoader().getResourceAsStream("comma-group.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("micronaut.security.ldap.default.enabled", true);
        configuration.put("micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort());
        configuration.put("micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com");
        configuration.put("micronaut.security.ldap.default.context.managerPassword", "password");
        configuration.put("micronaut.security.ldap.default.search.base", "dc=example,dc=com");
        configuration.put("micronaut.security.ldap.default.groups.enabled", true);
        configuration.put("micronaut.security.ldap.default.groups.base", "ou=groups,dc=example,dc=com");
        configuration.put("micronaut.security.ldap.default.groups.filter", "member={0}");
        context = ApplicationContext.run(configuration, "test");
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
        assertEquals(Collections.singleton("club-chess,payroll-admins"), new HashSet<>(roles));
        assertFalse(roles.contains("payroll-admins"));
        assertFalse(roles.contains("club-chess"));
    }

    @Test
    void memberOfTheRealGroupStillGetsItsRole() {
        Collection<String> roles = authenticate("gauss");
        assertEquals(Collections.singleton("payroll-admins"), new HashSet<>(roles));
    }

    private static Collection<String> authenticate(String username) {
        AuthenticationResponse response = Mono.from(authenticationProvider.authenticate(null, request(username))).block();
        assertTrue(response.isAuthenticated());
        Authentication authentication = response.getAuthentication().get();
        assertEquals(username, authentication.getName());
        return authentication.getRoles();
    }

    private static AuthenticationRequest<String, String> request(String username) {
        return new AuthenticationRequest<String, String>() {
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
