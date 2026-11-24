package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Replaces;
import io.micronaut.context.annotation.Requires;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.context.DefaultLdapSearchService;
import io.micronaut.security.ldap.context.LdapSearchResult;
import io.micronaut.security.ldap.context.SearchSettings;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A burst of anonymous requests with bogus credentials must not leave the directory
 * without free connections for the user binds of later, legitimate logins.
 * <p>
 * The directory accepts at most {@value #MAX_CONNECTIONS} concurrent connections. The burst
 * is exactly that wide, so the attack itself cannot be served, but once it is over the
 * provider must be able to authenticate a valid user again.
 */
class LdapConnectionPoolExhaustionTest {

    private static final String SPEC_NAME = "LdapConnectionPoolExhaustionTest";
    private static final int MAX_CONNECTIONS = 4;

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;
    private static LdapAuthenticationProvider<Object, String, String> authenticationProvider;
    private static BlockingLdapSearchService searchService;

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "password");
        config.setMaxConnections(MAX_CONNECTIONS);
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapConnectionPoolExhaustionTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        server.startListening();
        context = ApplicationContext.run(Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", "cn=admin,dc=example,dc=com",
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com"
        ), "test");
        authenticationProvider = context.getBean(LdapAuthenticationProvider.class);
        searchService = context.getBean(BlockingLdapSearchService.class);
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
    void validLoginStillWorksAfterAnonymousBurst() throws Exception {
        // Sanity check: a valid user authenticates before the burst
        assertTrue(authenticate("riemann", "password").isAuthenticated());

        // One burst of concurrent requests with unknown usernames, as wide as the directory allows.
        // Every request holds its manager context open until all of them have one.
        CyclicBarrier barrier = new CyclicBarrier(MAX_CONNECTIONS);
        searchService.barrier.set(barrier);
        ExecutorService executor = Executors.newFixedThreadPool(MAX_CONNECTIONS);
        try {
            List<Future<AuthenticationResponse>> burst = new ArrayList<>();
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                String bogusUser = "nobody-" + i;
                burst.add(executor.submit(() -> authenticate(bogusUser, "not-the-password")));
            }
            for (Future<AuthenticationResponse> future : burst) {
                AuthenticationResponse response = future.get(30, TimeUnit.SECONDS);
                assertFalse(response.isAuthenticated());
            }
        } finally {
            searchService.barrier.set(null);
            executor.shutdownNow();
        }

        // The burst is over: a user with the right password must be able to log in again
        AuthenticationResponse response = authenticate("riemann", "password");
        assertTrue(response.isAuthenticated(), () -> "login after the burst failed with " + response);
        assertEquals("riemann", response.getAuthentication().orElseThrow().getName());

        // and a wrong password is still rejected
        AuthenticationResponse rejected = authenticate("riemann", "not-the-password");
        assertFalse(rejected.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, rejected).getReason());
    }

    private static AuthenticationResponse authenticate(String username, String password) {
        return authenticationProvider.authenticate(null, new AuthenticationRequest<>() {
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

    /**
     * Holds every search of a burst until all of them are in flight, so that each request of the
     * burst owns its own manager connection at the same time, as it would under real load.
     */
    @Requires(property = "spec.name", value = SPEC_NAME)
    @Replaces(DefaultLdapSearchService.class)
    @Singleton
    static class BlockingLdapSearchService extends DefaultLdapSearchService {

        final AtomicReference<CyclicBarrier> barrier = new AtomicReference<>();

        @Override
        public Optional<LdapSearchResult> searchFirst(DirContext managerContext, SearchSettings settings) throws NamingException {
            CyclicBarrier currentBarrier = barrier.get();
            if (currentBarrier != null) {
                try {
                    currentBarrier.await(30, TimeUnit.SECONDS);
                } catch (Exception e) {
                    throw new IllegalStateException("Burst did not reach the directory concurrently", e);
                }
            }
            return super.searchFirst(managerContext, settings);
        }
    }
}
