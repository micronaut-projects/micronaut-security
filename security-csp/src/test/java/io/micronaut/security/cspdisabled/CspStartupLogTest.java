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
package io.micronaut.security.cspdisabled;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.security.csp.report.ContentSecurityPolicyReport;
import io.micronaut.security.csp.report.ContentSecurityPolicyReportHandler;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test
    void logsTheEnforcedHeaderAndPatternAtStartup() {
        List<ILoggingEvent> events = capture(STARTUP_LOGGER, () -> run(Map.of(), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.INFO, events.get(0).getLevel());
        assertTrue(events.get(0).getFormattedMessage().startsWith("Enforcing the Content-Security-Policy header on requests matching /**"));
    }

    @Test
    void logsReportOnlyModeAtStartup() {
        List<ILoggingEvent> events = capture(STARTUP_LOGGER, () -> run(Map.of("micronaut.security.csp.report-only", true), context -> { }));

        assertEquals(1, events.size());
        assertTrue(events.get(0).getFormattedMessage().startsWith("Writing the Content-Security-Policy-Report-Only header on requests matching /**"));
    }

    @Test
    void warnsWhenReportToHasNoEndpoint() {
        List<ILoggingEvent> events = capture(REPORT_TO_LOGGER, () -> run(Map.of("micronaut.security.csp.report-to.enabled", true), context -> { }));

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertTrue(events.get(0).getFormattedMessage().startsWith("CSP report-to is enabled with group 'csp'"));
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
    void warnsAboutMisquotedAndInvalidSourceExpressions() {
        List<ILoggingEvent> events = capture(GENERATOR_LOGGER, () -> run(Map.of(
            "micronaut.security.csp.script-src.values", List.of("self", "sha256-abc=", "https://a.example.com;img-src *", "'self'", "https://cdn.example.com")),
            context -> context.getBean(ContentSecurityPolicyGenerator.class)));

        assertEquals(List.of(
            "micronaut.security.csp.script-src.values contains \"self\", which looks like a keyword, hash or nonce source but is not single-quoted; browsers treat it as a host. Use \"'self'\".",
            "micronaut.security.csp.script-src.values contains \"sha256-abc=\", which looks like a keyword, hash or nonce source but is not single-quoted; browsers treat it as a host. Use \"'sha256-abc='\".",
            "micronaut.security.csp.script-src.values contains \"https://a.example.com;img-src *\", which has a ';' or ','; browsers read it as the end of the directive or policy. Configure each source expression as a separate value."),
            events.stream().map(ILoggingEvent::getFormattedMessage).toList());
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
        assertTrue(events.get(0).getFormattedMessage().startsWith("Omitting the CSP nonce from script-src: the ContentSecurityPolicyNonceGenerator bean"));
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
