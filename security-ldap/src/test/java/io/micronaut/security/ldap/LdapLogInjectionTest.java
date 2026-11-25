package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A line break in a value that is logged could start a forged log entry (CWE-117). The username is supplied by an
 * unauthenticated client, and the diagnostic messages and group names are supplied by the directory. None of them may
 * reach the log with its line breaks.
 */
class LdapLogInjectionTest {

    private static final String FORGED_ENTRY = "12:00:00 INFO  Authentication succeeded for admin";
    private static final String LINE_BREAKS = "\r\n";
    private static final String USER = "riemann";
    private static final String USER_DN = "uid=riemann," + LdapTestSupport.BASE_DN;

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLog() {
        logger = (Logger) LoggerFactory.getLogger("io.micronaut.security.ldap");
        originalLevel = logger.getLevel();
        logger.setLevel(Level.TRACE);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void restoreLog() {
        logger.detachAppender(appender);
        logger.setLevel(originalLevel);
    }

    @Test
    void lineBreaksInTheUsernameAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");

        AuthenticationResponse response = authenticate(server, Map.of(), "nobody" + LINE_BREAKS + FORGED_ENTRY + " ");

        assertFalse(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInTheDiagnosticMessageOfTheDirectoryAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif", new InMemoryOperationInterceptor() {
            @Override
            public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                if (USER_DN.equals(request.getRequest().getBindDN())) {
                    throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "denied" + LINE_BREAKS + FORGED_ENTRY);
                }
            }
        });

        AuthenticationResponse response = authenticate(server, Map.of(), USER);

        assertFalse(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @Test
    void lineBreaksInAGroupNameAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        server.add(new Entry("cn=forged," + LdapTestSupport.BASE_DN,
                new Attribute("objectClass", "groupOfUniqueNames"),
                new Attribute("cn", "forged", "staff" + LINE_BREAKS + FORGED_ENTRY),
                new Attribute("uniqueMember", USER_DN)));

        AuthenticationResponse response = authenticate(server, Map.of(
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN
        ), USER);

        assertTrue(response.isAuthenticated());
        assertForgedEntryIsLoggedWithoutLineBreaks();
    }

    @SuppressWarnings("unchecked")
    private static AuthenticationResponse authenticate(InMemoryDirectoryServer server, Map<String, Object> properties, String username) {
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, properties), "test")) {
            LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);
            return provider.authenticate(null, LdapTestSupport.request(username));
        } finally {
            server.shutDown(true);
        }
    }

    private void assertForgedEntryIsLoggedWithoutLineBreaks() {
        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.contains(FORGED_ENTRY)), "the value is expected in the log: " + messages);
        for (String message : messages) {
            assertFalse(message.matches("(?s).*[\\p{Cntrl}\\u2028\\u2029].*"), "control character logged: " + message);
        }
    }
}
