/*
 * Copyright 2026 original authors
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
package io.micronaut.security.filters;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityFilterConfigurationPatternTest {

    private static final String SPEC_NAME = "SecurityFilterConfigurationPatternTest";
    private static final String PATTERN_PROPERTY = "micronaut.security.filter.pattern";
    private static final String PATH_PROPERTY = "micronaut.security.filter.path";

    @Test
    void patternPropertyPopulatesTheConfigurationAndRestrictsTheSecurityFilter() {
        try (EmbeddedServer server = run(Map.of(PATTERN_PROPERTY, "/secured/**"));
             HttpClient httpClient = httpClient(server)) {
            BlockingHttpClient client = httpClient.toBlocking();

            assertEquals("/secured/**", pattern(server));
            assertEquals("Public", client.retrieve(get("/public")), "a path outside the pattern is not secured");
            assertEquals(HttpStatus.UNAUTHORIZED, statusOf(client, "/secured"));
        }
    }

    @Test
    void deprecatedPathPropertyPopulatesTheConfigurationButDoesNotChangeTheSecurityFilterPattern() {
        try (EmbeddedServer server = run(Map.of(PATH_PROPERTY, "/secured/**"));
             HttpClient httpClient = httpClient(server)) {
            BlockingHttpClient client = httpClient.toBlocking();

            assertEquals("/secured/**", pattern(server));
            assertEquals(HttpStatus.UNAUTHORIZED, statusOf(client, "/public"),
                "the filter still matches every path because it reads micronaut.security.filter.pattern");
        }
    }

    @Test
    void patternPropertyTakesPrecedenceOverTheDeprecatedPathProperty() {
        try (EmbeddedServer server = run(Map.of(PATTERN_PROPERTY, "/secured/**", PATH_PROPERTY, "/other/**"));
             HttpClient httpClient = httpClient(server)) {
            BlockingHttpClient client = httpClient.toBlocking();

            assertEquals("/secured/**", pattern(server));
            assertEquals("Public", client.retrieve(get("/public")));
            assertEquals(HttpStatus.UNAUTHORIZED, statusOf(client, "/secured"));
        }
    }

    @Test
    void patternDefaultsToMatchAll() {
        try (EmbeddedServer server = run(Map.of());
             HttpClient httpClient = httpClient(server)) {
            assertEquals("/**", pattern(server));
            assertEquals(HttpStatus.UNAUTHORIZED, statusOf(httpClient.toBlocking(), "/public"));
        }
    }

    @Test
    void blankPatternIsIgnored() {
        SecurityFilterConfigurationProperties configuration = new SecurityFilterConfigurationProperties();

        configuration.setPattern("");

        assertEquals("/**", configuration.getPattern());
    }

    private static EmbeddedServer run(Map<String, Object> properties) {
        Map<String, Object> configuration = new HashMap<>(properties);
        configuration.put("spec.name", SPEC_NAME);
        return ApplicationContext.run(EmbeddedServer.class, configuration);
    }

    private static HttpClient httpClient(EmbeddedServer server) {
        return server.getApplicationContext().createBean(HttpClient.class, server.getURL());
    }

    private static String pattern(EmbeddedServer server) {
        return server.getApplicationContext().getBean(SecurityFilterConfiguration.class).getPattern();
    }

    private static HttpRequest<?> get(String path) {
        return HttpRequest.GET(path).accept(MediaType.TEXT_PLAIN);
    }

    private static HttpStatus statusOf(BlockingHttpClient client, String path) {
        HttpRequest<?> request = get(path);
        return assertThrows(HttpClientResponseException.class, () -> client.retrieve(request)).getStatus();
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class PatternController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get("/public")
        String publicEndpoint() {
            return "Public";
        }

        @Secured(SecurityRule.IS_AUTHENTICATED)
        @Produces(MediaType.TEXT_PLAIN)
        @Get("/secured")
        String securedEndpoint() {
            return "Secured";
        }
    }
}
