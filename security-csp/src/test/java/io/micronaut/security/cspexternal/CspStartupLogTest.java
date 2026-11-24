/*
 * Copyright 2017-2026 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.security.cspexternal;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies the startup and runtime log messages that point developers at configuration that does
 * not do what they expect. Lives outside {@code io.micronaut.security.csp} so the module's package
 * requirements do not apply to the test beans.
 */
class CspStartupLogTest {
    private static final String STARTUP_LOGGER = "io.micronaut.security.csp.filters.ContentSecurityPolicyStartupLogger";
    private static final String REPORT_TO_LOGGER = "io.micronaut.security.csp.report.ReportToWithoutEndpointWarning";
    private static final String GENERATOR_LOGGER = "io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator";
    private static final String TOGGLE_LOGGER = "io.micronaut.security.csp.ToggleValueWarning";

    @Test
    void logsTheEnforcedHeaderAndPatternAtStartup() {
        List<ILoggingEvent> events = capture(STARTUP_LOGGER, () -> run(Map.of(), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.INFO, events.get(0).getLevel());
        assertMentions(events.get(0), "Content-Security-Policy header", "/**", "io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator");
        assertFalse(events.get(0).getFormattedMessage().contains("Report-Only"));
    }

    @Test
    void logsReportOnlyModeAtStartup() {
        List<ILoggingEvent> events = capture(STARTUP_LOGGER, () -> run(Map.of("micronaut.security.csp.report-only", true), context -> { }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), "Content-Security-Policy-Report-Only header", "/**", "browser console");
    }

    @ParameterizedTest
    @ValueSource(strings = {"micronaut.security.csp.report-uri.enabled", "micronaut.security.csp.report-to.enabled"})
    void logsThatViolationsAreReportedWhenReportingIsEnabled(String reportingProperty) {
        List<ILoggingEvent> events = capture(STARTUP_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.report-only", true,
            reportingProperty, true,
            "micronaut.security.csp.report-uri.values", List.of("https://reports.example.com/csp")), context -> { }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), "Content-Security-Policy-Report-Only header", "report-to group or report-uri");
    }

    @ParameterizedTest
    @CsvSource({
        "micronaut.security.csp.frame-ancestors.enabled, ture",
        "micronaut.security.csp.form-action.enabled, 1",
        "micronaut.security.csp.script-src.nonce, 1",
        "micronaut.security.csp.style-src.unsafe-inline, enabled",
        "micronaut.security.csp.img-src.data, t",
        "micronaut.security.csp.report-only, 0",
        "micronaut.security.csp.report-uri.enabled, x",
        "micronaut.security.csp.report-to.enabled, 1"
    })
    void failsStartupForAPolicySettingThatIsNotABoolean(String property, String value) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class,
            () -> ApplicationContext.run(Map.of(property, value)).close());

        String message = rootCause(exception).getMessage();
        assertTrue(message.startsWith(property + " is \"" + value + "\""), message);
        assertTrue(message.contains("not a boolean"), message);
    }

    @ParameterizedTest
    @ValueSource(strings = {"micronaut.security.csp.enabled", "micronaut.security.csp.filter.enabled",
        "micronaut.security.csp.report-to.controller.enabled"})
    void warnsThatAMistypedFeatureToggleKeepsTheFeatureEnabled(String property) {
        List<ILoggingEvent> events = capture(TOGGLE_LOGGER, () -> run(Map.of(property, "flase"), context -> { }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), property, "\"flase\"", "stays enabled");
    }

    @Test
    void nDisablesTheModuleLikeABoundBoolean() {
        try (ApplicationContext context = ApplicationContext.run(Map.of("micronaut.security.csp.enabled", "N"))) {
            assertFalse(context.containsBean(ContentSecurityPolicyGenerator.class));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"script-src", "style-src"})
    void pointsOutUnsafeInlineNextToANonceOrHash(String directive) {
        String prefix = "micronaut.security.csp." + directive;
        List<ILoggingEvent> withNonce = capture(GENERATOR_LOGGER, () -> run(Map.of(prefix + ".unsafe-inline", true, prefix + ".nonce", true), context -> { }));
        List<ILoggingEvent> withHash = capture(GENERATOR_LOGGER, () -> run(Map.of(prefix + ".unsafe-inline", true,
            prefix + ".values", List.of("'SHA256-abc='")), context -> { }));
        List<ILoggingEvent> alone = capture(GENERATOR_LOGGER, () -> run(Map.of(prefix + ".unsafe-inline", true), context -> { }));

        assertEquals(1, withNonce.size());
        assertEquals(Level.INFO, withNonce.get(0).getLevel());
        assertMentions(withNonce.get(0), prefix + ".unsafe-inline", "ignore 'unsafe-inline'");
        assertEquals(1, withHash.size());
        assertEquals(List.of(), alone);
    }

    @Test
    void warnsAboutStrictDynamicWithoutANonceOrHash() {
        List<ILoggingEvent> withoutAnchor = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.strict-dynamic", true,
            "micronaut.security.csp.script-src.self", true), context -> { }));
        List<ILoggingEvent> withNonce = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.strict-dynamic", true,
            "micronaut.security.csp.script-src.nonce", true), context -> { }));
        List<ILoggingEvent> disabled = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.strict-dynamic", true,
            "micronaut.security.csp.script-src.enabled", false), context -> { }));

        assertEquals(1, withoutAnchor.size());
        assertEquals(Level.WARN, withoutAnchor.get(0).getLevel());
        assertMentions(withoutAnchor.get(0), "micronaut.security.csp.script-src.strict-dynamic", "every script is blocked");
        assertEquals(List.of(), withNonce);
        assertEquals(List.of(), disabled);
    }

    @Test
    void theErrorForAnUnsafeValueShowsTheValue() {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class, () -> ApplicationContext.run(Map.of(
            "micronaut.security.csp.img-src.values", List.of("https://ok.example.com", "https://a.example; img-src\u00a0"))).close());

        assertTrue(rootCause(exception).getMessage().contains("\"https://a.example; img-src\\u00A0\""), () -> rootCause(exception).getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "FALSE", " yes ", "off", "n", "Y", "ON", "no"})
    void acceptsEverySpellingOfABooleanPolicySetting(String value) {
        assertDoesNotThrow(() -> run(Map.of(
            "micronaut.security.csp.report-to.enabled", value,
            "micronaut.security.csp.script-src.nonce", value,
            "micronaut.security.csp.frame-ancestors.enabled", value), context -> { }));
    }

    @Test
    void warnsWhenReportToHasNoEndpoint() {
        List<ILoggingEvent> events = capture(REPORT_TO_LOGGER, () -> run(Map.of("micronaut.security.csp.report-to.enabled", true), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertMentions(events.get(0), "report-to", "'csp'");
    }

    @Test
    void doesNotWarnWhenTheReportingGroupIsConfigured() {
        List<ILoggingEvent> events = capture(REPORT_TO_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.report-to.enabled", true,
            "micronaut.security.reporting-endpoints.csp.url", "https://reports.example.com/csp"), context -> { }));

        assertEquals(List.of(), events);
    }

    @Test
    void doesNotWarnWhenAReportHandlerExists() {
        List<ILoggingEvent> events = capture(REPORT_TO_LOGGER, () -> run(Map.of(
            "spec.name", "CspStartupLogTest",
            "micronaut.security.csp.report-to.enabled", true), context -> { }));

        assertEquals(List.of(), events);
    }

    @Test
    void warnsWhenAReportHandlerExistsButTheReportControllerIsDisabled() {
        List<ILoggingEvent> events = capture(REPORT_TO_LOGGER, () -> run(Map.of(
            "spec.name", "CspStartupLogTest",
            "micronaut.security.csp.report-to.enabled", true,
            "micronaut.security.csp.report-to.controller.enabled", false), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertMentions(events.get(0), "report-to", "'csp'", "enabled report controller");
    }

    @ParameterizedTest
    @ValueSource(strings = {"true", "TRUE", "yes"})
    void failsStartupWhenTheCspFilterOfMicronautViewsIsEnabledToo(String enabled) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class,
            () -> ApplicationContext.run(Map.of("micronaut.views.csp.enabled", enabled)).close());

        String message = rootCause(exception).getMessage();
        assertTrue(message.contains("cspNonce") && message.contains("micronaut.views.csp.enabled=false"), message);
    }

    @Test
    void startsWhenTheCspFilterOfMicronautViewsIsDisabled() {
        assertDoesNotThrow(() -> run(Map.of(), context -> { }));
        assertDoesNotThrow(() -> run(Map.of("micronaut.views.csp.enabled", "FALSE"), context -> { }));
    }

    @Test
    void startsWithMicronautViewsCspWhenTheModuleWritesNoHeader() {
        assertDoesNotThrow(() -> run(Map.of(
            "micronaut.views.csp.enabled", true,
            "micronaut.security.csp.filter.enabled", false), context -> { }));
    }

    @Test
    void warnsWhenReportUriIsEnabledWithoutValues() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.report-uri.enabled", true), context -> { }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), "micronaut.security.csp.report-uri.enabled", "micronaut.security.csp.report-uri.values", "omitted");
    }

    @Test
    void warnsWhenReportUrisAreConfiguredButTheDirectiveIsDisabled() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.report-uri.values", List.of("https://reports.example.com/csp")), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertMentions(events.get(0), "micronaut.security.csp.report-uri.values", "micronaut.security.csp.report-uri.enabled", "omitted");
    }

    @Test
    void warnsAboutAnUnquotedRequireTrustedTypesForValue() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.require-trusted-types-for.value", "script"), context -> { }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), "micronaut.security.csp.require-trusted-types-for.value", "\"script\"", "\"'script'\"");
    }

    @Test
    void doesNotWarnAboutTheDefaultRootSettings() {
        assertEquals(List.of(), capture(GENERATOR_LOGGER, () -> run(Map.of(), context -> { })));
    }

    @Test
    void warnsAboutMisquotedSourceExpressions() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.values", List.of("self", "sha256-abc=", "'self'", "https://cdn.example.com")),
            context -> { }));

        assertEquals(2, events.size(), "only the two unquoted expressions are reported");
        assertMentions(events.get(0), "micronaut.security.csp.script-src.values", "\"self\"", "\"'self'\"");
        assertMentions(events.get(1), "micronaut.security.csp.script-src.values", "\"sha256-abc=\"", "\"'sha256-abc='\"");
    }

    @Test
    void warnsAboutASourceExpressionWithoutItsClosingQuote() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.values", List.of("'self", "'", "'unsafe-inline'")),
            context -> { }));

        assertEquals(2, events.size(), "only the two expressions with an unclosed quote are reported");
        assertMentions(events.get(0), "micronaut.security.csp.script-src.values", "\"'self\"", "does not close it", "\"'self'\"");
        assertMentions(events.get(1), "micronaut.security.csp.script-src.values", "\"'\"", "does not close it");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unsafeConfigurations")
    void failsStartupForAValueThatWouldCorruptThePolicy(String property, Map<String, Object> properties) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class,
            () -> ApplicationContext.run(properties).close());

        assertTrue(rootCause(exception).getMessage().startsWith(property), () -> rootCause(exception).getMessage());
    }

    static Stream<Arguments> unsafeConfigurations() {
        return Stream.of(
            Arguments.of("micronaut.security.csp.img-src.values", Map.of(
                "micronaut.security.csp.img-src.values", List.of("https://a.example.com; script-src *"))),
            Arguments.of("micronaut.security.csp.script-src.values", Map.of(
                "micronaut.security.csp.script-src.values", List.of("https://a.example.com, script-src *"))),
            Arguments.of("micronaut.security.csp.style-src.values", Map.of(
                "micronaut.security.csp.style-src.values", List.of("https://a.example.com\r\nX-Injected: 1"))),
            Arguments.of("micronaut.security.csp.report-uri.values", Map.of(
                "micronaut.security.csp.report-uri.enabled", true,
                "micronaut.security.csp.report-uri.values", List.of("https://a.example.com/r; script-src *"))),
            Arguments.of("micronaut.security.csp.require-trusted-types-for.value", Map.of(
                "micronaut.security.csp.require-trusted-types-for.value", "'script'; script-src *"))
        );
    }

    private static Throwable rootCause(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }

    @Test
    void warnsAboutAPlaintextReportUriOnANonLoopbackHost() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.report-uri.enabled", true,
            "micronaut.security.csp.report-uri.values", List.of("http://reports.example.com/csp", "HTTP://localhost:8080/csp", "https://reports.example.com/csp", "/csp")),
            context -> { }));

        assertEquals(1, events.size(), "only the plaintext endpoint on a non-loopback host is reported");
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertMentions(events.get(0), "micronaut.security.csp.report-uri.values", "http://reports.example.com/csp");
    }

    @Test
    void warnsOnceAboutAnInvalidNonce() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of("micronaut.security.csp.script-src.nonce", true), context -> {
            ContentSecurityPolicyGenerator generator = context.getBean(ContentSecurityPolicyGenerator.class);
            for (int i = 0; i < 2; i++) {
                MutableHttpRequest<?> request = HttpRequest.GET("/");
                request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, "not a nonce");
                generator.contentSecurityPolicy(request);
            }
        }));

        assertEquals(1, events.size());
        assertMentions(events.get(0), "script-src", "ContentSecurityPolicyNonceGenerator");
    }

    /**
     * Asserts on the facts a log message must carry, not on its wording.
     */
    private static void assertMentions(ILoggingEvent event, String... facts) {
        String message = event.getFormattedMessage();
        for (String fact : facts) {
            assertTrue(message.contains(fact), () -> "expected \"" + fact + "\" in: " + message);
        }
    }

    private static void run(Map<String, Object> properties, Consumer<ApplicationContext> action) {
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            action.accept(context);
        }
    }

    private static List<ILoggingEvent> capture(String loggerName, Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(loggerName);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream().filter(event -> event.getLevel().isGreaterOrEqual(Level.INFO)).toList();
    }

    @Requires(property = "spec.name", value = "CspStartupLogTest")
    @Singleton
    static class NoOpReportHandler implements ContentSecurityPolicyReportHandler {
        @Override
        public void handle(List<ContentSecurityPolicyReport> reports, HttpRequest<?> request) {
        }
    }
}
