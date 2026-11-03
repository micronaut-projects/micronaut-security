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
package io.micronaut.security.rules;

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.annotation.Secured;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IpPatternsRuleServerTest {

    private static final String SPEC_NAME = "IpPatternsRuleServerTest";

    @Test
    void loopbackLiteralPatternAdmitsLoopbackRequests() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration(Arrays.asList("127.0.0.1", "0:0:0:0:0:0:0:1")));
             HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.GET("/anonymous"), String.class);
            assertEquals(HttpStatus.OK, response.getStatus());
            assertEquals("anonymous", response.body());
        }
    }

    @Test
    void wildcardPatternOutsideLoopbackRejectsLoopbackRequests() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration(Collections.singletonList("192.168.1.*")));
             HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> client.toBlocking().exchange(HttpRequest.GET("/anonymous"), String.class));
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
        }
    }

    @Test
    void dotsInWildcardPatternsAreLiteral() {
        // As a regular expression, "12.*" is "12" followed by anything and admits 127.0.0.1. As an IP wildcard the dot
        // is literal, so only addresses starting with "12." match and the loopback request is rejected.
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration(Collections.singletonList("12.*")));
             HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpClientResponseException e = assertThrows(HttpClientResponseException.class,
                () -> client.toBlocking().exchange(HttpRequest.GET("/anonymous"), String.class));
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
        }
    }

    private static Map<String, Object> configuration(List<String> ipPatterns) {
        Map<String, Object> configuration = new HashMap<>();
        configuration.put("spec.name", SPEC_NAME);
        configuration.put("micronaut.security.ip-patterns", ipPatterns);
        return configuration;
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/anonymous")
    @Secured(SecurityRule.IS_ANONYMOUS)
    static class AnonymousController {

        @Produces(MediaType.TEXT_PLAIN)
        @Get
        String index() {
            return "anonymous";
        }
    }
}
