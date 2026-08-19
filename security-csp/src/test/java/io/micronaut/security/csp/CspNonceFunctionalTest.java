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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.views.View;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CspNonceFunctionalTest {
    private static final String SPEC_NAME = "CspNonceFunctionalTest";
    private static final Pattern SCRIPT_NONCE = Pattern.compile("<script nonce=\"([^\"]+)\">");

    @Test
    void responseHeaderNonceMatchesViewModelNonce() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", SPEC_NAME))) {
            try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);
                Matcher matcher = SCRIPT_NONCE.matcher(response.body());

                assertTrue(matcher.find());
                assertTrue(response.header("Content-Security-Policy").contains("script-src 'nonce-" + matcher.group(1) + "'"));
            }
        }
    }

    @Test
    void doesNotAddNonceWhenDisabled() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.script-src-nonce-enabled", false))) {
            try (HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
                BlockingHttpClient client = httpClient.toBlocking();
                HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);

                assertFalse(response.header("Content-Security-Policy").contains("script-src"));
                assertFalse(SCRIPT_NONCE.matcher(response.body()).find());
            }
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class CspNonceController {

        @View("csp-nonce")
        @Get
        Map<String, Object> index() {
            return Map.of();
        }
    }
}
