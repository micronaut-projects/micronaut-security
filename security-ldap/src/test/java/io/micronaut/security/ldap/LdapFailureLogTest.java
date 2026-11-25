package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Map;

import static io.micronaut.security.ldap.LdapTestSupport.failureReason;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Every failure of {@link LdapAuthenticationProvider} is logged with the step that failed, the reason returned and
 * the exception, including its root cause: {@link javax.naming.NamingException#getMessage()} carries only the
 * explanation, such as the address of the directory, whereas the root cause, such as a refused connection or a failed
 * TLS handshake, is what an operator needs to diagnose an {@link AuthenticationFailureReason#UNKNOWN} failure.
 */
class LdapFailureLogTest {

    private static final String USER = "riemann";
    private static final String USER_DN = "uid=riemann," + LdapTestSupport.BASE_DN;

    private LogCapture log;

    @BeforeEach
    void captureLog() {
        log = LogCapture.start(LdapAuthenticationProvider.class.getName(), Level.DEBUG);
    }

    @AfterEach
    void restoreLog() {
        log.close();
    }

    @Test
    void theRootCauseOfAnUnreachableDirectoryIsLogged() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of(
                // nothing listens on the port any more, so the connection is refused
                "micronaut.security.ldap.default.context.server", "ldap://localhost:" + closedPort
        )), "test")) {
            assertEquals(AuthenticationFailureReason.UNKNOWN, authenticate(context, LdapTestSupport.PASSWORD));
        } finally {
            server.shutDown(true);
        }

        assertLogged(Level.DEBUG, "LDAP manager bind failed for user [riemann]; returning UNKNOWN.", "CommunicationException", "ConnectException");
    }

    @Test
    void aFailingUserSearchIsLoggedAsSuch() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", new InMemoryOperationInterceptor() {
            @Override
            public void processSearchRequest(InMemoryInterceptedSearchRequest request) throws LDAPException {
                if (request.getRequest().getScope() == SearchScope.SUB) {
                    throw new LDAPException(ResultCode.UNAVAILABLE, "simulated unavailable");
                }
            }
        });

        assertEquals(AuthenticationFailureReason.UNKNOWN, authenticate(server, Map.of(), LdapTestSupport.PASSWORD));
        assertLogged(Level.DEBUG, "LDAP user search failed for user [riemann]; returning UNKNOWN.", "ServiceUnavailableException");
    }

    @Test
    void anOutageDuringTheUserBindIsLoggedAsSuch() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", new InMemoryOperationInterceptor() {
            @Override
            public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                if (USER_DN.equals(request.getRequest().getBindDN())) {
                    throw new LDAPException(ResultCode.BUSY, "simulated busy");
                }
            }
        });

        assertEquals(AuthenticationFailureReason.UNKNOWN, authenticate(server, Map.of(), LdapTestSupport.PASSWORD));
        assertLogged(Level.DEBUG, "LDAP user bind failed for user [riemann]; returning UNKNOWN.", "ServiceUnavailableException");
    }

    @Test
    void aFailingGroupSearchIsLoggedAtWarnAfterASuccessfulBind() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");

        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, authenticate(server, Map.of(
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN,
                // not a valid search filter, so the group search fails after the user bind succeeded
                "micronaut.security.ldap.default.groups.filter", "((("
        ), LdapTestSupport.PASSWORD));

        assertTrue(log.messages().stream().anyMatch(message -> message.startsWith("Successfully bound user")), "the bind is expected to succeed: " + log.messages());
        // only a client with the correct password reaches the group search, whose failure usually means a misconfiguration
        assertLogged(Level.WARN, "LDAP group search failed for user [riemann] after a successful bind; returning CREDENTIALS_DO_NOT_MATCH.", "InvalidSearchFilterException");
    }

    @Test
    void aRejectedUserBindStatesTheReasonItReturns() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");

        assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH, authenticate(server, Map.of(), "wrong"));
        assertLogged(Level.DEBUG, "LDAP user bind failed for user [riemann]; returning CREDENTIALS_DO_NOT_MATCH.", "AuthenticationException");
    }

    private static AuthenticationFailureReason authenticate(InMemoryDirectoryServer server, Map<String, Object> properties, String password) {
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, properties), "test")) {
            return authenticate(context, password);
        } finally {
            server.shutDown(true);
        }
    }

    private static AuthenticationFailureReason authenticate(ApplicationContext context, String password) {
        return failureReason(LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request(USER, password)));
    }

    private void assertLogged(Level level, String prefix, String... fragments) {
        assertTrue(log.events().stream().anyMatch(event -> event.getLevel() == level
                        && event.getFormattedMessage().startsWith(prefix)
                        && Arrays.stream(fragments).allMatch(event.getFormattedMessage()::contains)),
                "expected a " + level + " message starting with [" + prefix + "] and containing " + Arrays.toString(fragments) + ": " + log.messages());
    }
}
