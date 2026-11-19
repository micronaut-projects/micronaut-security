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
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.views.View;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CspNonceFunctionalTest {
    private static final String SPEC_NAME = "CspNonceFunctionalTest";
    private static final Pattern SCRIPT_NONCE = Pattern.compile("<script nonce=\"([^\"]+)\">");
    private static final int REQUESTS = 3;

    @Test
    void responseHeaderNonceMatchesViewModelNonce() {
        withClient(Map.of("micronaut.security.csp.script-src.nonce", true), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);

            assertEquals(nonceSource(viewNonce(response)), policy(response).scriptSrc().value());
        });
    }

    @Test
    void everyRequestGetsADifferentNonce() {
        withClient(Map.of("micronaut.security.csp.script-src.nonce", true), client -> {
            Set<String> nonces = new HashSet<>();
            for (int i = 0; i < REQUESTS; i++) {
                HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);
                String nonce = viewNonce(response);
                assertEquals(nonceSource(nonce), policy(response).scriptSrc().value(), "header and view must use the same nonce");
                nonces.add(nonce);
            }
            assertEquals(REQUESTS, nonces.size(), "a nonce must never be reused across requests: " + nonces);
        });
    }

    @Test
    void controllerReadsTheSameNonceFromTheRequestAttribute() {
        withClient(Map.of("micronaut.security.csp.script-src.nonce", true), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/nonce-attribute"), String.class);

            assertNotNull(response.body(), "the controller must see the nonce request attribute");
            assertEquals(nonceSource(response.body()), policy(response).scriptSrc().value());
        });
    }

    @Test
    void generatesNonceWhenOnlyStyleSrcNonceIsEnabled() {
        withClient(Map.of("micronaut.security.csp.style-src.nonce", true), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);
            ContentSecurityPolicy policy = policy(response);

            assertEquals(nonceSource(viewNonce(response)), policy.styleSrc().value());
            assertEquals("'none'", policy.scriptSrc().value());
        });
    }

    @Test
    void scriptSrcAndStyleSrcShareTheSameNonce() {
        withClient(Map.of(
                "micronaut.security.csp.script-src.nonce", true,
                "micronaut.security.csp.style-src.nonce", true), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);
            ContentSecurityPolicy policy = policy(response);
            String expected = nonceSource(viewNonce(response));

            assertEquals(expected, policy.scriptSrc().value());
            assertEquals(expected, policy.styleSrc().value());
        });
    }

    @Test
    void addsStrictDynamicToScriptSrcWhenEnabled() {
        withClient(Map.of(
                "micronaut.security.csp.script-src.nonce", true,
                "micronaut.security.csp.script-src.strict-dynamic", true), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);

            assertEquals(nonceSource(viewNonce(response)) + " 'strict-dynamic'", policy(response).scriptSrc().value());
        });
    }

    @Test
    void doesNotGenerateANonceForADisabledDirective() {
        withClient(Map.of(
                "micronaut.security.csp.script-src.nonce", true,
                "micronaut.security.csp.script-src.enabled", false), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/nonce-attribute"), String.class);

            assertEquals("no nonce", response.body());
            assertNull(policy(response).scriptSrc());
        });
    }

    @Test
    void doesNotAddNonceByDefault() {
        withClient(Map.of(), client -> {
            HttpResponse<String> response = client.exchange(HttpRequest.GET("/"), String.class);

            assertEquals("'none'", policy(response).scriptSrc().value());
            assertFalse(SCRIPT_NONCE.matcher(response.body()).find(), "no nonce may be rendered when nonces are disabled");
        });
    }

    private static void withClient(Map<String, Object> properties, Consumer<BlockingHttpClient> test) {
        Map<String, Object> configuration = new HashMap<>(properties);
        configuration.put("spec.name", SPEC_NAME);
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, configuration);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            test.accept(httpClient.toBlocking());
        }
    }

    private static ContentSecurityPolicy policy(HttpResponse<?> response) {
        ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);
        assertNotNull(policy, "the response must carry a Content-Security-Policy header");
        return policy;
    }

    private static String viewNonce(HttpResponse<String> response) {
        String body = response.body();
        assertNotNull(body, "the view must render a body");
        Matcher matcher = SCRIPT_NONCE.matcher(body);
        assertTrue(matcher.find(), "the view must render a script nonce: " + body);
        return matcher.group(1);
    }

    private static String nonceSource(String nonce) {
        return "'nonce-" + nonce + "'";
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class CspNonceController {

        @View("csp-nonce")
        @Get
        Map<String, Object> index() {
            return Map.of();
        }

        @Get("/nonce-attribute")
        @Produces(MediaType.TEXT_PLAIN)
        String nonceAttribute(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse("no nonce");
        }
    }
}
