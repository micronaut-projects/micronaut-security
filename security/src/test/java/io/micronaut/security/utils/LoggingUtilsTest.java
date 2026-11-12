package io.micronaut.security.utils;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.security.authentication.Authentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoggingUtilsTest {

    private static final String SECRET = "secret-value";
    private static final String EMAIL = "alice@example.com";
    private static final String MESSAGE_PREFIX = "Authentication attributes:";

    private Logger logger;
    private Level originalLevel;
    private ListAppender<ILoggingEvent> appender;

    @BeforeEach
    void setup() {
        logger = (Logger) LoggerFactory.getLogger(LoggingUtilsTest.class);
        originalLevel = logger.getLevel();
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void cleanup() {
        logger.detachAppender(appender);
        appender.stop();
        logger.setLevel(originalLevel);
    }

    @Test
    void nullAuthenticationIsNotLogged() {
        logger.setLevel(Level.TRACE);
        assertDoesNotThrow(() -> LoggingUtils.logAuthenticationAttributes(logger, null));
        assertTrue(appender.list.isEmpty());
    }

    @Test
    void nothingIsLoggedIfLevelIsAboveDebug() {
        logger.setLevel(Level.INFO);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", Map.of("accessToken", SECRET, "email", EMAIL)));
        assertTrue(appender.list.isEmpty());
    }

    @Test
    void atDebugOnlyTheAttributeKeysAreLogged() {
        logger.setLevel(Level.DEBUG);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", Map.of("accessToken", SECRET, "email", EMAIL)));

        assertEquals(1, appender.list.size());
        assertEquals(Level.DEBUG, appender.list.get(0).getLevel());
        String message = appender.list.get(0).getFormattedMessage();
        assertTrue(message.startsWith(MESSAGE_PREFIX));
        assertTrue(message.contains("accessToken"));
        assertTrue(message.contains("email"));
        assertFalse(message.contains(SECRET));
        assertFalse(message.contains(EMAIL));
    }

    @Test
    void atTraceNonSensitiveAttributeValuesAreLogged() {
        logger.setLevel(Level.TRACE);
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("email", EMAIL);
        attributes.put("age", 30);
        attributes.put("nickname", null);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", attributes));

        assertEquals(1, appender.list.size());
        assertEquals(Level.TRACE, appender.list.get(0).getLevel());
        String message = appender.list.get(0).getFormattedMessage();
        assertTrue(message.startsWith(MESSAGE_PREFIX));
        assertTrue(message.contains("email=>" + EMAIL));
        assertTrue(message.contains("age=>30"));
        assertTrue(message.contains("nickname=>null"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"accessToken", "refreshToken", "openIdToken", "ACCESSTOKEN", "accesstoken", "X-Custom-Token", "id_token", "TOKEN"})
    void atTraceTokenValuesAreRedacted(String key) {
        logger.setLevel(Level.TRACE);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", Map.of(key, SECRET)));

        assertEquals(1, appender.list.size());
        String message = appender.list.get(0).getFormattedMessage();
        assertTrue(message.contains(key + "=><redacted>"));
        assertFalse(message.contains(SECRET));
    }

    @ParameterizedTest
    @ValueSource(strings = {"email", "tokenType", "token_expiry"})
    void atTraceValuesOfKeysNotNamingATokenAreNotRedacted(String key) {
        logger.setLevel(Level.TRACE);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", Map.of(key, "visible-value")));

        assertEquals(1, appender.list.size());
        assertTrue(appender.list.get(0).getFormattedMessage().contains(key + "=>visible-value"));
    }

    @Test
    void atTraceNullTokenValueIsLoggedAsNull() {
        logger.setLevel(Level.TRACE);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("accessToken", null);
        LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice", attributes));

        assertEquals(1, appender.list.size());
        assertTrue(appender.list.get(0).getFormattedMessage().contains("accessToken=>null"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"DEBUG", "TRACE"})
    void authenticationWithoutAttributesIsLogged(String level) {
        logger.setLevel(Level.toLevel(level));
        assertDoesNotThrow(() -> LoggingUtils.logAuthenticationAttributes(logger, Authentication.build("alice")));

        assertEquals(1, appender.list.size());
        assertTrue(appender.list.get(0).getFormattedMessage().startsWith(MESSAGE_PREFIX));
    }
}
