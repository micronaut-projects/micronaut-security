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
package io.micronaut.security.csp.report;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpRequest;
import io.micronaut.runtime.context.scope.refresh.RefreshEvent;
import io.micronaut.security.csp.conf.reportto.ReportToConfigurationProperties;
import io.micronaut.security.reporting.ReportingEndpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CspReportingEndpointProviderTest {

    @ParameterizedTest
    @ValueSource(strings = {"", "//other-host.example/x", "relative/path", "csp/report", "/csp report", "/csp\"report", "/csp\\report"})
    void rejectsAPathThatIsNotALocalAbsolutePath(String path) {
        ContentSecurityPolicyControllerConfigurationProperties controller = new ContentSecurityPolicyControllerConfigurationProperties();
        controller.setPath(path);

        assertThrows(ConfigurationException.class, () -> provider(enabledReportTo(), controller, List.of()));
        assertTrue(!path.matches(ContentSecurityPolicyControllerConfigurationProperties.LOCAL_PATH_REGEX),
            "the bean-validation constraint of the property must reject the same paths");
    }

    @ParameterizedTest
    @ValueSource(strings = {"CSP", "csp group", "csp;x", "1csp"})
    void rejectsAGroupThatReportingEndpointsCannotCarry(String group) {
        ReportToConfigurationProperties reportTo = enabledReportTo();
        reportTo.setGroup(group);

        ConfigurationException exception = assertThrows(ConfigurationException.class,
            () -> provider(reportTo, new ContentSecurityPolicyControllerConfigurationProperties(), List.of()));

        assertEquals("micronaut.security.csp.report-to.group must match " + ReportToConfigurationProperties.GROUP_REGEX
            + ", the grammar of a Reporting-Endpoints name", exception.getMessage());
    }

    @Test
    void advertisesALocalPath() {
        ContentSecurityPolicyControllerConfigurationProperties controller = new ContentSecurityPolicyControllerConfigurationProperties();
        controller.setPath("/reports/csp");

        ReportingEndpoint endpoint = provider(enabledReportTo(), controller, List.of()).reportingEndpoint(HttpRequest.GET("/"));

        assertNotNull(endpoint);
        assertEquals("csp", endpoint.getName());
        assertEquals(URI.create("/reports/csp"), endpoint.getUrl());
    }

    @Test
    void followsARefreshedGroupSoThatItKeepsMatchingTheReportToDirective() {
        ReportToConfigurationProperties reportTo = enabledReportTo();
        CspReportingEndpointProvider provider = provider(reportTo, new ContentSecurityPolicyControllerConfigurationProperties(), List.of());
        assertEquals(Set.of(ReportToConfigurationProperties.PREFIX), provider.getObservedConfigurationPrefixes());

        reportTo.setGroup("csp2");
        provider.onApplicationEvent(new RefreshEvent(Map.of(ReportToConfigurationProperties.PREFIX + ".group", "csp")));

        assertEquals("csp2", provider.reportingEndpoint(HttpRequest.GET("/")).getName());
    }

    @Test
    void keepsThePreviousGroupWhenTheRefreshedOneIsInvalid() {
        ReportToConfigurationProperties reportTo = enabledReportTo();
        CspReportingEndpointProvider provider = provider(reportTo, new ContentSecurityPolicyControllerConfigurationProperties(), List.of());

        reportTo.setGroup("CSP 2");
        List<ILoggingEvent> events = capture(() -> provider.onApplicationEvent(new RefreshEvent(Map.of())));

        assertEquals("csp", provider.reportingEndpoint(HttpRequest.GET("/")).getName());
        assertEquals(1, events.size());
        assertEquals(Level.ERROR, events.get(0).getLevel());
    }

    @Test
    void defersToAConfiguredEndpointWithTheSameNameAndWarnsWhenItReceivesTheReportsElsewhere() {
        List<ILoggingEvent> events = capture(() -> {
            CspReportingEndpointProvider provider = provider(enabledReportTo(), new ContentSecurityPolicyControllerConfigurationProperties(),
                List.of(endpoint("csp", "https://reports.example.com/csp")));

            assertNull(provider.reportingEndpoint(HttpRequest.GET("/")), "the Reporting API module would warn about a duplicate name on every response");
        });

        assertEquals(1, events.size());
        assertEquals(Level.WARN, events.get(0).getLevel());
        assertTrue(events.get(0).getFormattedMessage().contains("https://reports.example.com/csp"), events.get(0)::getFormattedMessage);
        assertTrue(events.get(0).getFormattedMessage().contains("/csp/report"), events.get(0)::getFormattedMessage);
    }

    @Test
    void defersSilentlyToAConfiguredEndpointForTheController() {
        List<ILoggingEvent> events = capture(() -> {
            CspReportingEndpointProvider provider = provider(enabledReportTo(), new ContentSecurityPolicyControllerConfigurationProperties(),
                List.of(endpoint("other", "/other"), endpoint("csp", "/csp/report")));

            assertNull(provider.reportingEndpoint(HttpRequest.GET("/")));
        });

        assertEquals(List.of(), events);
    }

    @Test
    void advertisesTheControllerNextToConfiguredEndpointsWithOtherNames() {
        CspReportingEndpointProvider provider = provider(enabledReportTo(), new ContentSecurityPolicyControllerConfigurationProperties(),
            List.of(endpoint("other", "/other")));

        assertEquals("csp", provider.reportingEndpoint(HttpRequest.GET("/")).getName());
    }

    private static CspReportingEndpointProvider provider(ReportToConfigurationProperties reportTo,
                                                         ContentSecurityPolicyControllerConfigurationProperties controller,
                                                         List<ReportingEndpoint> staticEndpoints) {
        return new CspReportingEndpointProvider(reportTo, controller, null, staticEndpoints);
    }

    private static ReportingEndpoint endpoint(String name, String url) {
        return new ReportingEndpoint() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public URI getUrl() {
                return URI.create(url);
            }
        };
    }

    private static ReportToConfigurationProperties enabledReportTo() {
        ReportToConfigurationProperties reportTo = new ReportToConfigurationProperties();
        reportTo.setEnabled(true);
        return reportTo;
    }

    private static List<ILoggingEvent> capture(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(CspReportingEndpointProvider.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list;
    }
}
