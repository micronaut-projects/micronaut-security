package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationFailureReason;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static io.micronaut.security.ldap.LdapTestSupport.failureReason;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link javax.naming.NamingException#getMessage()} carries only the explanation of a JNDI failure, such as the
 * address of the directory. The root cause, such as a refused connection or a failed TLS handshake, is what an
 * operator needs to diagnose an {@link AuthenticationFailureReason#UNKNOWN} failure, so it has to reach the log.
 */
class LdapFailureLogTest {

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLog() {
        logger = (Logger) LoggerFactory.getLogger(LdapAuthenticationProvider.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.DEBUG);
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
    void theRootCauseOfAnUnreachableDirectoryIsLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        Map<String, Object> properties = LdapTestSupport.properties(server);
        // nothing listens on the port any more, so the connection is refused
        server.shutDown(true);

        try (ApplicationContext context = ApplicationContext.run(properties, "test")) {
            assertEquals(AuthenticationFailureReason.UNKNOWN,
                    failureReason(LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request("riemann"))));
        }

        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("LDAP manager bind failed for user [riemann]; returning UNKNOWN.")
                        && message.contains("CommunicationException") && message.contains("ConnectException")),
                "the failing step, the exception type and its root cause are expected in the log: " + messages);
    }

    @Test
    void aFailingGroupSearchIsLoggedAsSuchAfterASuccessfulBind() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server, Map.of(
                "micronaut.security.ldap.default.groups.enabled", true,
                "micronaut.security.ldap.default.groups.base", LdapTestSupport.BASE_DN,
                // not a valid search filter, so the group search fails after the user bind succeeded
                "micronaut.security.ldap.default.groups.filter", "((("
        )), "test")) {
            assertEquals(AuthenticationFailureReason.UNKNOWN,
                    failureReason(LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request("riemann"))));
        } finally {
            server.shutDown(true);
        }

        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("Successfully bound user")), "the bind is expected to succeed: " + messages);
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("LDAP group search failed for user [riemann]; returning UNKNOWN.")),
                "the log is expected to blame the group search, not the user: " + messages);
    }

    @Test
    void aRejectedUserBindStatesTheReasonItReturns() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server), "test")) {
            assertEquals(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH,
                    failureReason(LdapTestSupport.provider(context).authenticate(null, LdapTestSupport.request("riemann", "wrong"))));
        } finally {
            server.shutDown(true);
        }

        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.startsWith("Directory rejected the bind of user [riemann]; returning CREDENTIALS_DO_NOT_MATCH.")
                        && message.contains("AuthenticationException")),
                "the log is expected to name the reason returned: " + messages);
    }
}
