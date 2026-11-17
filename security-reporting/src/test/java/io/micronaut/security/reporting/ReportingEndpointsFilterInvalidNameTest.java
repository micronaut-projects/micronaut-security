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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ReportingEndpointsFilterInvalidNameTest {
    private static final String PROVIDER_SPEC = "ReportingEndpointsFilterInvalidNameTest.provider";
    private static final String STATIC_SPEC = "ReportingEndpointsFilterInvalidNameTest.static";

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
