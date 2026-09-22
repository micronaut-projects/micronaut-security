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
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsrfRepositoryEnabledConditionTest {

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
            assertTrue(ctx.containsBean(CookieCsrfTokenRepository.class));
            assertTrue(ctx.containsBean(SessionCsrfTokenRepository.class));
        }
        assertTrue(warnings().isEmpty());
    }

    @Test
    void canonicalKeyFalseDisablesRepositoryCookie() {
        canonicalKeyFalseDisablesRepository("cookie");
    }

    @Test
    void canonicalKeyFalseDisablesRepositorySession() {
        canonicalKeyFalseDisablesRepository("session");
    }

    private void canonicalKeyFalseDisablesRepository(String name) {
        appender.list.clear();
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.csrf.repositories." + name + ".enabled", false))) {
            assertEquals(!"cookie".equals(name), ctx.containsBean(CookieCsrfTokenRepository.class));
            assertEquals(!"session".equals(name), ctx.containsBean(SessionCsrfTokenRepository.class));
        }
        assertTrue(warnings().isEmpty());
    }

    @Test
    void legacyKeyFalseDisablesRepositoryAndLogsWarningCookie() {
        legacyKeyFalseDisablesRepositoryAndLogsWarning("cookie");
    }

    @Test
    void legacyKeyFalseDisablesRepositoryAndLogsWarningSession() {
        legacyKeyFalseDisablesRepositoryAndLogsWarning("session");
    }

    private void legacyKeyFalseDisablesRepositoryAndLogsWarning(String name) {
        appender.list.clear();
        try (ApplicationContext ctx = ApplicationContext.run(Map.of("micronaut.security.csrf.repository." + name + ".enabled", false))) {
            assertEquals(!"cookie".equals(name), ctx.containsBean(CookieCsrfTokenRepository.class));
            assertEquals(!"session".equals(name), ctx.containsBean(SessionCsrfTokenRepository.class));
            assertFalse(ctx.getBeansOfType(CsrfTokenRepository.class).isEmpty());
        }
        List<String> warnings = warnings();
        assertEquals(1, warnings.size(), warnings.toString());
        assertEquals("Configuration property [micronaut.security.csrf.repository." + name + ".enabled] is deprecated. Use [micronaut.security.csrf.repositories." + name + ".enabled] instead.", warnings.get(0));
    }

    @Test
    void canonicalKeyTrueOverridesLegacyKeyFalseCookie() {
        canonicalKeyTrueOverridesLegacyKeyFalse("cookie");
    }

    @Test
    void canonicalKeyTrueOverridesLegacyKeyFalseSession() {
        canonicalKeyTrueOverridesLegacyKeyFalse("session");
    }

    private void canonicalKeyTrueOverridesLegacyKeyFalse(String name) {
        appender.list.clear();
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
            "micronaut.security.csrf.repositories." + name + ".enabled", true,
            "micronaut.security.csrf.repository." + name + ".enabled", false))) {
            assertTrue(ctx.containsBean(CookieCsrfTokenRepository.class));
            assertTrue(ctx.containsBean(SessionCsrfTokenRepository.class));
        }
        assertTrue(warnings().isEmpty());
    }

    private List<String> warnings() {
        return appender.list.stream()
            .filter(e -> e.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    }
}
