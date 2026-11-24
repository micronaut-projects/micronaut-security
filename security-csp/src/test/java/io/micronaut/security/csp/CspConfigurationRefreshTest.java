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
package io.micronaut.security.csp;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.env.PropertySource;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.runtime.context.scope.refresh.RefreshEvent;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The generator caches the directives it builds from the configuration, so a configuration refresh
 * must rebuild them, and must not let refreshed values skip the startup checks.
 */
class CspConfigurationRefreshTest {
    private static final String SPEC_NAME = "CspConfigurationRefreshTest";

    @Test
    void aRefreshedDirectiveConfigurationTakesEffectOnTheNextPolicy() {
        Map<String, Object> properties = new HashMap<>(Map.of(
            "micronaut.security.csp.img-src.values", List.of("https://a.example.com"),
            "micronaut.security.csp.script-src.nonce", true));
        try (ApplicationContext context = ApplicationContext.builder().propertySources(PropertySource.of("refreshable", properties)).start()) {
            ContentSecurityPolicyGenerator generator = context.getBean(ContentSecurityPolicyGenerator.class);
            assertEquals("img-src https://a.example.com", policy(generator).imgSrc().toHeaderValue());

            properties.put("micronaut.security.csp.img-src.values", List.of("https://b.example.com"));
            properties.put("micronaut.security.csp.script-src.self", true);
            properties.put("micronaut.security.csp.report-uri.enabled", true);
            properties.put("micronaut.security.csp.report-uri.values", List.of("https://reports.example.com/csp"));
            refresh(context);

            ContentSecurityPolicy refreshed = policy(generator);
            assertEquals("img-src https://b.example.com", refreshed.imgSrc().toHeaderValue());
            assertEquals("script-src 'nonce-requestnonce' 'self'", refreshed.scriptSrc().toHeaderValue(), "the nonce is still added per request");
            assertEquals("report-uri https://reports.example.com/csp", refreshed.reportUri().toHeaderValue());
        }
    }

    @Test
    void anInvalidRefreshedValueIsRejectedAndThePreviousPolicyIsKept() {
        Map<String, Object> properties = new HashMap<>(Map.of("micronaut.security.csp.img-src.values", List.of("https://a.example.com")));
        try (ApplicationContext context = ApplicationContext.builder().propertySources(PropertySource.of("refreshable", properties)).start()) {
            ContentSecurityPolicyGenerator generator = context.getBean(ContentSecurityPolicyGenerator.class);

            properties.put("micronaut.security.csp.img-src.values", List.of("https://b.example.com; script-src *"));
            List<ILoggingEvent> events = captureErrors(() -> refresh(context));

            assertEquals("img-src https://a.example.com", policy(generator).imgSrc().toHeaderValue());
            assertEquals(1, events.size());
            assertTrue(events.get(0).getFormattedMessage().contains("micronaut.security.csp.img-src.values"), events.get(0)::getFormattedMessage);
        }
    }

    @Test
    void enablingNoncesInARefreshAddsTheNonceWithoutARestart() {
        Map<String, Object> properties = new HashMap<>(Map.of(
            "spec.name", SPEC_NAME,
            "micronaut.security.csp.script-src.self", true));
        try (ApplicationContext context = ApplicationContext.builder().propertySources(PropertySource.of("refreshable", properties)).start();
             EmbeddedServer server = context.getBean(EmbeddedServer.class).start();
             HttpClient httpClient = context.createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> before = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-refresh"), String.class);
            assertEquals("script-src 'self'", ContentSecurityPolicy.of(before).scriptSrc().toHeaderValue());

            properties.put("micronaut.security.csp.script-src.nonce", true);
            refresh(context);

            HttpResponse<String> after = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-refresh"), String.class);
            assertEquals("script-src 'nonce-" + after.body() + "' 'self'", ContentSecurityPolicy.of(after).scriptSrc().toHeaderValue(),
                "the template and the header must receive the same nonce");
            assertEquals("private", after.header(HttpHeaders.CACHE_CONTROL));
        }
    }

    @Test
    void reportOnlyModeChangesWithTheRefreshedPolicyOnly() {
        Map<String, Object> properties = new HashMap<>(Map.of("spec.name", SPEC_NAME));
        try (ApplicationContext context = ApplicationContext.builder().propertySources(PropertySource.of("refreshable", properties)).start();
             EmbeddedServer server = context.getBean(EmbeddedServer.class).start();
             HttpClient httpClient = context.createBean(HttpClient.class, server.getURL())) {
            properties.put("micronaut.security.csp.report-only", true);
            properties.put("micronaut.security.csp.img-src.values", List.of("https://a.example.com; script-src *"));
            captureErrors(() -> refresh(context));

            HttpResponse<String> rejected = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-refresh"), String.class);
            assertNotNull(rejected.header(HttpHeaders.CONTENT_SECURITY_POLICY), "the previous policy keeps being enforced");
            assertNull(rejected.header(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY));

            properties.put("micronaut.security.csp.img-src.values", List.of("https://a.example.com"));
            refresh(context);

            HttpResponse<String> accepted = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-refresh"), String.class);
            assertNull(accepted.header(HttpHeaders.CONTENT_SECURITY_POLICY));
            assertEquals("img-src https://a.example.com",
                ContentSecurityPolicy.of(accepted.getHeaders(), HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY).imgSrc().toHeaderValue());
        }
    }

    @Test
    void warnsThatTheReportEndpointNeedsARestartWhenARefreshTogglesReportTo() {
        Map<String, Object> properties = new HashMap<>();
        try (ApplicationContext context = ApplicationContext.builder().propertySources(PropertySource.of("refreshable", properties)).start()) {
            ContentSecurityPolicyGenerator generator = context.getBean(ContentSecurityPolicyGenerator.class);

            properties.put("micronaut.security.csp.report-to.enabled", true);
            List<ILoggingEvent> warnings = capture(Level.WARN, () -> refresh(context));

            assertEquals("report-to csp", policy(generator).reportTo().toHeaderValue());
            assertEquals(1, warnings.size());
            assertTrue(warnings.get(0).getFormattedMessage().contains("micronaut.security.csp.report-to.enabled"), warnings.get(0)::getFormattedMessage);

            properties.put("micronaut.security.csp.img-src.self", true);
            assertEquals(List.of(), capture(Level.WARN, () -> refresh(context)), "only a change of report-to.enabled is reported");
        }
    }

    private static void refresh(ApplicationContext context) {
        Map<String, Object> changes = context.getEnvironment().refreshAndDiff();
        context.publishEvent(new RefreshEvent(changes));
    }

    private static ContentSecurityPolicy policy(ContentSecurityPolicyGenerator generator) {
        MutableHttpRequest<?> request = HttpRequest.GET("/");
        request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, "requestnonce");
        return generator.contentSecurityPolicy(request);
    }

    private static List<ILoggingEvent> captureErrors(Runnable action) {
        return capture(Level.ERROR, action);
    }

    private static List<ILoggingEvent> capture(Level level, Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(DefaultContentSecurityPolicyGenerator.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list.stream().filter(event -> event.getLevel() == level).toList();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/csp-refresh")
    static class RefreshController {
        @Get
        @Produces(MediaType.TEXT_HTML)
        String index(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse("no nonce");
        }
    }
}
