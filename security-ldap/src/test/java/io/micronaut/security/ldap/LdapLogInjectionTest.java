package io.micronaut.security.ldap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.authentication.AuthenticationResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The username is supplied by an unauthenticated client. A line break in it must not reach the log, where it could
 * start a forged log entry (CWE-117).
 */
class LdapLogInjectionTest {

    private static final String FORGED_ENTRY = "12:00:00 INFO  Authentication succeeded for admin";
    private static final String USERNAME = "nobody\r\n" + FORGED_ENTRY + " ";

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void captureLog() {
        logger = (Logger) LoggerFactory.getLogger(LdapAuthenticationProvider.class);
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
    @SuppressWarnings("unchecked")
    void lineBreaksInTheUsernameAreNotLogged() throws Exception {
        InMemoryDirectoryServer server = LdapTestSupport.startServer("basic.ldif");
        try (ApplicationContext context = ApplicationContext.run(LdapTestSupport.properties(server), "test")) {
            LdapAuthenticationProvider<Object, String, String> provider = context.getBean(LdapAuthenticationProvider.class);

            AuthenticationResponse response = provider.authenticate(null, LdapTestSupport.request(USERNAME));

            assertFalse(response.isAuthenticated());
        } finally {
            server.shutDown(true);
        }
        List<String> messages = appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertTrue(messages.stream().anyMatch(message -> message.contains(FORGED_ENTRY)), "the username is expected in the log: " + messages);
        for (String message : messages) {
            assertFalse(message.matches("(?s).*[\\p{Cntrl}\\u2028\\u2029].*"), "control character logged: " + message);
        }
    }
}
