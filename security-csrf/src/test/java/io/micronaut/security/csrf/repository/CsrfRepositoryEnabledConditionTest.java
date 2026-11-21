package io.micronaut.security.csrf.repository;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.exceptions.NoSuchBeanException;
import io.micronaut.security.csrf.session.SessionCsrfTokenRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
            assertDisabledBy(ctx, name, canonicalKey(name), "false");
        }
        assertTrue(warnings().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void legacyKeyFalseDisablesRepositoryAndLogsWarning(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(legacyKey(name), false))) {
            assertOnlyDisabled(ctx, name);
            assertDisabledBy(ctx, name, legacyKey(name), "false");
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
        assertEquals(List.of(ignoredWarning(name)), warnings());
    }

    @ParameterizedTest
    @ValueSource(strings = {COOKIE, SESSION})
    void canonicalKeyFalseOverridesLegacyKeyTrue(String name) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
            canonicalKey(name), false,
            legacyKey(name), true))) {
            assertOnlyDisabled(ctx, name);
            assertDisabledBy(ctx, name, canonicalKey(name), "false");
        }
        assertEquals(List.of(ignoredWarning(name)), warnings());
    }

    @ParameterizedTest
    @CsvSource({
        "cookie, TRUE", "cookie, yes", "cookie, on", "cookie, y",
        "session, TRUE", "session, yes", "session, on", "session, y"
    })
    void booleanLikeValueKeepsRepositoryEnabled(String name, String value) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(canonicalKey(name), value))) {
            assertBothEnabled(ctx);
        }
    }

    @ParameterizedTest
    @CsvSource({
        "cookie, off", "cookie, no", "cookie, disabled", "cookie, ''", "cookie, '   '",
        "session, off", "session, no", "session, disabled", "session, ''", "session, '   '"
    })
    void otherValueDisablesRepository(String name, String value) {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(canonicalKey(name), value))) {
            assertOnlyDisabled(ctx, name);
            assertDisabledBy(ctx, name, canonicalKey(name), value);
        }
    }

    @Test
    void warningIsLoggedOncePerApplicationContext() {
        for (int i = 0; i < 2; i++) {
            try (ApplicationContext ctx = ApplicationContext.run(Map.of(legacyKey(COOKIE), false))) {
                // every lookup of the disabled bean evaluates the condition again
                for (int j = 0; j < 3; j++) {
                    assertOnlyDisabled(ctx, COOKIE);
                    assertThrows(NoSuchBeanException.class, () -> ctx.getBean(CookieCsrfTokenRepository.class));
                }
            }
        }
        assertEquals(List.of(deprecationWarning(COOKIE), deprecationWarning(COOKIE)), warnings());
    }

    @Test
    void eachDeprecatedKeyWarnsOnceInTheSameContext() {
        try (ApplicationContext ctx = ApplicationContext.run(Map.of(
            legacyKey(COOKIE), true,
            legacyKey(SESSION), true))) {
            assertBothEnabled(ctx);
            assertBothEnabled(ctx);
        }
        List<String> warnings = warnings();
        assertEquals(2, warnings.size(), () -> "Expected one warning per deprecated key: " + warnings);
        assertTrue(warnings.containsAll(List.of(deprecationWarning(COOKIE), deprecationWarning(SESSION))), () -> "Unexpected warnings: " + warnings);
    }

    @Test
    void contextsOpenAtTheSameTimeWarnIndependently() {
        Map<String, Object> config = Map.of(legacyKey(COOKIE), false);
        try (ApplicationContext first = ApplicationContext.run(config);
             ApplicationContext second = ApplicationContext.run(config)) {
            assertOnlyDisabled(first, COOKIE);
            assertOnlyDisabled(second, COOKIE);
            assertOnlyDisabled(first, COOKIE);
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

    private static String ignoredWarning(String name) {
        return "Configuration property [" + legacyKey(name) + "] is deprecated and ignored because [" + canonicalKey(name) + "] is set. Remove it.";
    }

    private static void assertBothEnabled(ApplicationContext ctx) {
        assertTrue(ctx.containsBean(CookieCsrfTokenRepository.class));
        assertTrue(ctx.containsBean(SessionCsrfTokenRepository.class));
    }

    private static void assertOnlyDisabled(ApplicationContext ctx, String name) {
        assertEquals(!COOKIE.equals(name), ctx.containsBean(CookieCsrfTokenRepository.class));
        assertEquals(!SESSION.equals(name), ctx.containsBean(SessionCsrfTokenRepository.class));
    }

    private static void assertDisabledBy(ApplicationContext ctx, String name, String key, String value) {
        Class<?> repository = COOKIE.equals(name) ? CookieCsrfTokenRepository.class : SessionCsrfTokenRepository.class;
        NoSuchBeanException e = assertThrows(NoSuchBeanException.class, () -> ctx.getBean(repository));
        String reason = "Property [" + key + "] is set to [" + value + "], which disables the repository. Only true, yes, y or on enable it.";
        assertTrue(e.getMessage().contains(reason), () -> "Expected [" + reason + "] in: " + e.getMessage());
    }

    private List<String> warnings() {
        return appender.list.stream()
            .filter(e -> e.getLevel() == Level.WARN)
            .map(ILoggingEvent::getFormattedMessage)
            .toList();
    }
}
