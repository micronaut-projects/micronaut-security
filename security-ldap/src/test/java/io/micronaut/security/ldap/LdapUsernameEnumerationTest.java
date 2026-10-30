package io.micronaut.security.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldif.LDIFReader;
import io.micronaut.context.ApplicationContext;
import io.micronaut.inject.qualifiers.Qualifiers;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.security.authentication.AuthenticationException;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import io.micronaut.security.authentication.AuthenticationRequest;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.ldap.configuration.LdapConfiguration;
import io.micronaut.security.ldap.context.ContextBuilder;
import io.micronaut.security.ldap.context.ContextSettings;
import io.micronaut.security.ldap.context.LdapSearchService;
import io.micronaut.security.ldap.group.LdapGroupProcessor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * An unauthenticated client must not be able to tell whether a username exists in the
 * directory: an unknown username and a wrong password must produce the same failure, and
 * both must cost a bind round trip to the directory.
 */
class LdapUsernameEnumerationTest {

    private static final String MANAGER_DN = "cn=admin,dc=example,dc=com";
    private static final String EXISTING_USER = "euclid";
    private static final String UNKNOWN_USER = "nobody-in-this-directory";
    private static final String DECOY_DN = "cn=decoy,dc=example,dc=com";
    private static final String DECOY_PASSWORD = "test-fixture-unmatchable-decoy-password";

    private static InMemoryDirectoryServer server;
    private static ApplicationContext context;

    @BeforeAll
    static void setup() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.addAdditionalBindCredentials(MANAGER_DN, "password");
        server = new InMemoryDirectoryServer(config);
        try (InputStream ldif = LdapUsernameEnumerationTest.class.getClassLoader().getResourceAsStream("basic.ldif")) {
            server.importFromLDIF(true, new LDIFReader(ldif));
        }
        // a real decoy entry whose password no client is expected to submit; it has no uid, so the user search filter never matches it
        server.add("dn: " + DECOY_DN,
                "objectclass: inetOrgPerson",
                "cn: decoy",
                "sn: decoy",
                "userPassword: " + DECOY_PASSWORD);
        server.startListening();
        context = ApplicationContext.run(properties(), "test");
    }

    private static Map<String, Object> properties() {
        return Map.of(
                "micronaut.security.ldap.default.enabled", true,
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + server.getListenPort(),
                "micronaut.security.ldap.default.context.managerDn", MANAGER_DN,
                "micronaut.security.ldap.default.context.managerPassword", "password",
                "micronaut.security.ldap.default.search.base", "dc=example,dc=com",
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", "dc=example,dc=com"
        );
    }

    private static Map<String, Object> propertiesWithDecoyDn(String decoyDn) {
        Map<String, Object> properties = new HashMap<>(properties());
        properties.put("micronaut.security.ldap.default.search.decoy-dn", decoyDn);
        return properties;
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
    void unknownUsernameAndWrongPasswordFailIdentically() {
        LdapAuthenticationProvider<Object> provider = context.getBean(LdapAuthenticationProvider.class);

        AuthenticationResponse unknownUser = authenticate(provider, request(UNKNOWN_USER, "password"));
        AuthenticationResponse wrongPassword = authenticate(provider, request(EXISTING_USER, "wrong-password"));

        assertFalse(unknownUser.isAuthenticated());
        assertFalse(wrongPassword.isAuthenticated());
        AuthenticationFailed unknownUserFailure = assertInstanceOf(AuthenticationFailed.class, unknownUser);
        AuthenticationFailed wrongPasswordFailure = assertInstanceOf(AuthenticationFailed.class, wrongPassword);
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, wrongPasswordFailure.getReason());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, unknownUserFailure.getReason());
        assertNotEquals(AuthenticationFailureReason.USER_NOT_FOUND, unknownUserFailure.getReason());
        assertEquals(wrongPassword.getMessage(), unknownUser.getMessage());
        assertEquals(wrongPasswordFailure, unknownUserFailure);
    }

    @Test
    @SuppressWarnings("unchecked")
    void validCredentialsStillAuthenticate() {
        LdapAuthenticationProvider<Object> provider = context.getBean(LdapAuthenticationProvider.class);

        AuthenticationResponse response = authenticate(provider, request(EXISTING_USER, "password"));

        assertTrue(response.isAuthenticated());
        assertEquals(EXISTING_USER, response.getAuthentication().orElseThrow().getName());
    }

    @Test
    void unknownUsernameStillCostsABindRoundTrip() {
        RecordingContextBuilder contextBuilder = new RecordingContextBuilder(context.getBean(ContextBuilder.class));
        LdapAuthenticationProvider<Object> provider = provider(contextBuilder);

        AuthenticationResponse unknownUser = authenticate(provider, request(UNKNOWN_USER, "password"));

        assertFalse(unknownUser.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, unknownUser).getReason());
        assertEquals(1, contextBuilder.userBinds.size(), "exactly one non-manager bind is expected for an unknown username");
        ContextSettings dummyBind = contextBuilder.userBinds.get(0);
        assertNotEquals(MANAGER_DN, dummyBind.getDn());
        assertFalse(dummyBind.getDn().isBlank());
        assertTrue(dummyBind.getDn().endsWith(",dc=example,dc=com"), "the decoy DN lives under the search base");
        assertEquals("password", dummyBind.getPassword());

        contextBuilder.userBinds.clear();
        authenticate(provider, request(EXISTING_USER, "wrong-password"));
        assertEquals(1, contextBuilder.userBinds.size(), "a wrong password costs exactly one bind too");
        assertEquals("uid=euclid,dc=example,dc=com", contextBuilder.userBinds.get(0).getDn());
    }

    @Test
    void placeholderBindFailureDoesNotChangeTheFailureReason() {
        ContextBuilder delegate = context.getBean(ContextBuilder.class);
        ContextBuilder failingUserBinds = new RecordingContextBuilder(delegate) {
            @Override
            public DirContext build(ContextSettings contextSettings) throws NamingException {
                if (!MANAGER_DN.equals(contextSettings.getDn())) {
                    throw new CommunicationException("simulated connection loss");
                }
                return super.build(contextSettings);
            }
        };
        LdapAuthenticationProvider<Object> provider = provider(failingUserBinds);

        AuthenticationResponse unknownUser = authenticate(provider, request(UNKNOWN_USER, "password"));

        assertFalse(unknownUser.isAuthenticated());
        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, unknownUser).getReason());
    }

    @Test
    void defaultDecoyDnIsRandomPerAttempt() {
        RecordingContextBuilder contextBuilder = new RecordingContextBuilder(context.getBean(ContextBuilder.class));
        LdapAuthenticationProvider<Object> provider = provider(contextBuilder);

        authenticate(provider, request(UNKNOWN_USER, "password"));
        authenticate(provider, request(UNKNOWN_USER, "password"));

        assertEquals(2, contextBuilder.userBinds.size());
        assertNotEquals(contextBuilder.userBinds.get(0).getDn(), contextBuilder.userBinds.get(1).getDn());
    }

    @Test
    void configuredDecoyDnIsBound() {
        try (ApplicationContext decoyContext = ApplicationContext.run(propertiesWithDecoyDn("uid=does-not-exist,dc=example,dc=com"), "test")) {
            RecordingContextBuilder contextBuilder = new RecordingContextBuilder(decoyContext.getBean(ContextBuilder.class));

            AuthenticationResponse unknownUser = authenticate(provider(decoyContext, contextBuilder), request(UNKNOWN_USER, "password"));

            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, assertInstanceOf(AuthenticationFailed.class, unknownUser).getReason());
            assertEquals(1, contextBuilder.userBinds.size());
            assertEquals("uid=does-not-exist,dc=example,dc=com", contextBuilder.userBinds.get(0).getDn());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void realDecoyEntryNeverAuthenticatesAndKeepsTheFailureReason() {
        try (ApplicationContext decoyContext = ApplicationContext.run(propertiesWithDecoyDn(DECOY_DN), "test")) {
            LdapAuthenticationProvider<Object> provider = decoyContext.getBean(LdapAuthenticationProvider.class);

            // the usual case: the decoy bind is rejected by the directory with invalid credentials
            AuthenticationResponse wrongDecoyPassword = authenticate(provider, request(UNKNOWN_USER, "password"));
            // the decoy password leaked or was guessed: the decoy bind succeeds, but the response must still be a failure
            AuthenticationResponse matchingDecoyPassword = authenticate(provider, request(UNKNOWN_USER, DECOY_PASSWORD));
            // a known user with a wrong password is still indistinguishable from both
            AuthenticationResponse wrongPassword = authenticate(provider, request(EXISTING_USER, "wrong-password"));
            // and the decoy entry itself cannot be used to log in by its uid
            AuthenticationResponse decoyLogin = authenticate(provider, request("decoy", DECOY_PASSWORD));

            assertFalse(wrongDecoyPassword.isAuthenticated());
            assertFalse(matchingDecoyPassword.isAuthenticated());
            assertFalse(decoyLogin.isAuthenticated());
            assertEquals(assertInstanceOf(AuthenticationFailed.class, wrongPassword), assertInstanceOf(AuthenticationFailed.class, wrongDecoyPassword));
            assertEquals(assertInstanceOf(AuthenticationFailed.class, wrongPassword), assertInstanceOf(AuthenticationFailed.class, matchingDecoyPassword));
            assertEquals(assertInstanceOf(AuthenticationFailed.class, wrongPassword), assertInstanceOf(AuthenticationFailed.class, decoyLogin));
        }
    }

    @Test
    void rejectUnknownUserReceivesTheRequest() {
        List<String> seen = new ArrayList<>();
        LdapAuthenticationProvider<Object> provider = new LdapAuthenticationProvider<>(
                context.getBean(LdapConfiguration.class),
                context.getBean(LdapSearchService.class),
                context.getBean(ContextBuilder.class),
                context.getBean(ContextAuthenticationMapper.class),
                context.getBean(LdapGroupProcessor.class),
                context.getBean(ExecutorService.class, Qualifiers.byName(TaskExecutors.IO))) {
            @Override
            protected AuthenticationResponse rejectUnknownUser(Object requestContext, AuthenticationRequest<?, ?> authenticationRequest) {
                seen.add(authenticationRequest.getIdentity().toString());
                return super.rejectUnknownUser(requestContext, authenticationRequest);
            }
        };

        authenticate(provider, request(UNKNOWN_USER, "password"));
        authenticate(provider, request(EXISTING_USER, "wrong-password"));

        assertEquals(List.of(UNKNOWN_USER), seen);
    }

    private static LdapAuthenticationProvider<Object> provider(ContextBuilder contextBuilder) {
        return provider(context, contextBuilder);
    }

    private static LdapAuthenticationProvider<Object> provider(ApplicationContext context, ContextBuilder contextBuilder) {
        return new LdapAuthenticationProvider<>(
                context.getBean(LdapConfiguration.class),
                context.getBean(LdapSearchService.class),
                contextBuilder,
                context.getBean(ContextAuthenticationMapper.class),
                context.getBean(LdapGroupProcessor.class),
                context.getBean(ExecutorService.class, Qualifiers.byName(TaskExecutors.IO)));
    }

    private static AuthenticationResponse authenticate(LdapAuthenticationProvider<Object> provider, AuthenticationRequest<?, ?> request) {
        // on 4.x the provider is reactive and signals a failure as an AuthenticationException carrying the response
        return Mono.from(provider.authenticate(null, request))
                .onErrorResume(AuthenticationException.class, e -> Mono.just(e.getResponse()))
                .block();
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

    private static class RecordingContextBuilder implements ContextBuilder {
        final List<ContextSettings> userBinds = new ArrayList<>();
        private final ContextBuilder delegate;

        RecordingContextBuilder(ContextBuilder delegate) {
            this.delegate = delegate;
        }

        @Override
        public DirContext build(ContextSettings contextSettings) throws NamingException {
            if (!MANAGER_DN.equals(contextSettings.getDn())) {
                userBinds.add(contextSettings);
            }
            return delegate.build(contextSettings);
        }

        @Override
        public DirContext build(String factory, String server, String user, String password, boolean pooled) throws NamingException {
            return delegate.build(factory, server, user, password, pooled);
        }

        @Override
        public void close(DirContext context) {
            delegate.close(context);
        }
    }
}
