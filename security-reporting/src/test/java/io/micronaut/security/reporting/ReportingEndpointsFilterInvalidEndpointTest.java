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
package io.micronaut.security.reporting;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportingEndpointsFilterInvalidEndpointTest {
    private static final String PROVIDER_SPEC = "ReportingEndpointsFilterInvalidEndpointTest.provider";
    private static final String STATIC_SPEC = "ReportingEndpointsFilterInvalidEndpointTest.static";

    @Test
    void omitsAProviderEndpointWithAnInvalidNameWithoutFailingTheResponse() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", PROVIDER_SPEC,
                ReportingEndpointConfiguration.PREFIX + ".csp.url", "/csp/report"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpResponse<?> response = client.exchange(HttpRequest.GET("/invalid-name?tenant=Acme"));

            assertEquals(HttpStatus.OK, response.status());
            assertEquals("csp=\"/csp/report\"", response.header(ReportingEndpoints.HEADER_NAME));

            HttpResponse<?> valid = client.exchange(HttpRequest.GET("/invalid-name?tenant=acme"));

            assertEquals("acme=\"/reports/acme\", csp=\"/csp/report\"", valid.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void omitsAConfiguredEndpointWithoutAUrlWithoutFailingTheResponse() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", PROVIDER_SPEC,
                ReportingEndpointConfiguration.PREFIX + ".network.uri", "/typo",
                ReportingEndpointConfiguration.PREFIX + ".csp.url", "/csp/report"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/invalid-name?tenant=acme"));

            assertEquals(HttpStatus.OK, response.status());
            assertEquals("acme=\"/reports/acme\", csp=\"/csp/report\"", response.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void omitsTheHeaderWhenTheOnlyConfiguredEndpointHasNoUrl() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", STATIC_SPEC,
                ReportingEndpointConfiguration.PREFIX + ".network.uri", "/typo"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/invalid-static-name"));

            assertEquals(HttpStatus.OK, response.status());
            assertNull(response.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void warnsForEachRejectedProviderEndpointWithoutLoggingItsName() {
        Logger logger = (Logger) LoggerFactory.getLogger(ReportingEndpointsFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            client.exchange(HttpRequest.GET("/invalid-name?tenant=Acme"));
            client.exchange(HttpRequest.GET("/invalid-name?tenant=Other"));

            List<String> warnings = appender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
            assertEquals(2, warnings.size(), warnings.toString());
            for (String warning : warnings) {
                assertTrue(warning.contains(TenantReportingEndpointProvider.class.getName()), warning);
                assertFalse(warning.contains("Acme") || warning.contains("Other"), warning);
            }
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void omitsTheHeaderWhenTheOnlyEndpointHasAnInvalidName() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", PROVIDER_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/invalid-name?tenant=Acme"));

            assertEquals(HttpStatus.OK, response.status());
            assertNull(response.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void omitsAStaticEndpointBeanWithAnInvalidNameWithoutFailingTheResponse() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", STATIC_SPEC,
                ReportingEndpointConfiguration.PREFIX + ".csp.url", "/csp/report"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/invalid-static-name"));

            assertEquals(HttpStatus.OK, response.status());
            assertEquals("csp=\"/csp/report\"", response.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    @Test
    void warnsOnceForAStaticEndpointThatIsOmitted() {
        Logger logger = (Logger) LoggerFactory.getLogger(ReportingEndpointsFilter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            ReportingEndpointsFilter filter = new ReportingEndpointsFilter(
                List.of(endpoint("Csp"), endpoint("network")), List.of());
            MutableHttpResponse<?> first = HttpResponse.ok();
            MutableHttpResponse<?> second = HttpResponse.ok();

            filter.filter(HttpRequest.GET("/"), first);
            filter.filter(HttpRequest.GET("/"), second);

            assertEquals("network=\"/reports/network\"", first.getHeaders().get(ReportingEndpoints.HEADER_NAME));
            assertEquals("network=\"/reports/network\"", second.getHeaders().get(ReportingEndpoints.HEADER_NAME));
            List<String> warnings = appender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .map(ILoggingEvent::getFormattedMessage)
                .toList();
            assertEquals(1, warnings.size(), warnings.toString());
            assertTrue(warnings.get(0).contains("\"Csp\""), warnings.get(0));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void omitsTheHeaderWhenTheOnlyStaticEndpointHasAnInvalidName() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", STATIC_SPEC));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<?> response = httpClient.toBlocking().exchange(HttpRequest.GET("/invalid-static-name"));

            assertEquals(HttpStatus.OK, response.status());
            assertNull(response.header(ReportingEndpoints.HEADER_NAME));
        }
    }

    private static ReportingEndpoint endpoint(String name) {
        return new ReportingEndpoint() {
            @Override
            public String getName() {
                return name;
            }

            @Override
            public URI getUrl() {
                return URI.create("/reports/" + name);
            }
        };
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC)
    @Controller("/invalid-name")
    static final class TestController {
        @Get
        String index() {
            return "ok";
        }
    }

    @Requires(property = "spec.name", value = PROVIDER_SPEC)
    @Singleton
    static final class TenantReportingEndpointProvider implements ReportingEndpointProvider {
        @Override
        public ReportingEndpoint reportingEndpoint(HttpRequest<?> request) {
            return endpoint(request.getParameters().get("tenant"));
        }
    }

    @Requires(property = "spec.name", value = STATIC_SPEC)
    @Controller("/invalid-static-name")
    static final class StaticTestController {
        @Get
        String index() {
            return "ok";
        }
    }

    @Requires(property = "spec.name", value = STATIC_SPEC)
    @Singleton
    static final class InvalidStaticReportingEndpoint implements ReportingEndpoint {
        @Override
        public String getName() {
            return "Csp";
        }

        @Override
        public URI getUrl() {
            return URI.create("/csp/report");
        }
    }
}
