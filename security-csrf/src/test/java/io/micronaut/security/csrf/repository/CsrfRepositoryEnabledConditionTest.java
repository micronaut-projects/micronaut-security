package io.micronaut.security.csrf.repository;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.security.csrf.session.SessionCsrfTokenRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsrfRepositoryEnabledConditionTest {

    private static final String COOKIE = "cookie";
    private static final String SESSION = "session";

    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(CsrfRepositoryEnabledCondition.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
        appender.stop();
    }

    @Test
    void bothKeysUnsetKeepsBothRepositoriesEnabled() {
        try (ApplicationContext ctx = ApplicationContext.run()) {
            assertBothEnabled(ctx);
        }
        assertTrue(warnings().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void canonicalKeyFalseDisablesRepository(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(canonicalKey(name), false))) {
            assertOnlyDisabled(ctx, name);
        }
        assertTrue(warnings().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void legacyKeyFalseDisablesRepositoryAndLogsWarning(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(legacyKey(name), false))) {
            assertOnlyDisabled(ctx, name);
        }
        assertEquals(List.of(deprecationWarning(name)), warnings());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void legacyKeyTrueKeepsRepositoryEnabledAndLogsWarning(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(legacyKey(name), true))) {
            assertBothEnabled(ctx);
        }
        assertEquals(List.of(deprecationWarning(name)), warnings());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void canonicalKeyTrueOverridesLegacyKeyFalse(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
            canonicalKey(name), true,
            legacyKey(name), false))) {
            assertBothEnabled(ctx);
        }
        assertTrue(warnings().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void canonicalKeyFalseOverridesLegacyKeyTrue(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
            canonicalKey(name), false,
            legacyKey(name), true))) {
            assertOnlyDisabled(ctx, name);
        }
        assertTrue(warnings().isEmpty());
    }

    @Test
    void warningIsLoggedOncePerApplicationContext() {
        for (int i = 0; i < 2; i++) {
            try (ApplicationContext ctx = ApplicationContext.run(Map.of(legacyKey(COOKIE), false))) {
                assertOnlyDisabled(ctx, COOKIE);
            }
        }
        assertEquals(List.of(deprecationWarning(COOKIE), deprecationWarning(COOKIE)), warnings());
    }

    private static String canonicalKey(String name) {
        return "micronaut.security.csrf.repositories." + name + ".enabled";
    }

    private static String legacyKey(String name) {
        return "micronaut.security.csrf.repository." + name + ".enabled";
    }

    private static String deprecationWarning(String name) {
        return "Configuration property [" + legacyKey(name) + "] is deprecated. Use [" + canonicalKey(name) + "] instead.";
    }

    private static void assertBothEnabled(ApplicationContext ctx) {
        assertTrue(ctx.containsBean(CookieCsrfTokenRepository.class));
        assertTrue(ctx.containsBean(SessionCsrfTokenRepository.class));
    }

    private static void assertOnlyDisabled(ApplicationContext ctx, String name) {
        assertEquals(!COOKIE.equals(name), ctx.containsBean(CookieCsrfTokenRepository.class));
        assertEquals(!SESSION.equals(name), ctx.containsBean(SessionCsrfTokenRepository.class));
    }

    private List<String> warnings() {
        return appender.list.stream()
            .filter(e -> e.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    }
}
