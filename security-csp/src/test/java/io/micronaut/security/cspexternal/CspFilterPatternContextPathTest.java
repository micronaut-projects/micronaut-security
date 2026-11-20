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

import io.micronaut.context.ApplicationContext;
import io.micronaut.context.annotation.Requires;
import io.micronaut.context.exceptions.BeanInstantiationException;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A narrowed {@code filter.pattern} must select the same requests for the nonce filter and the
 * response header, with and without a server context path.
 */
class CspFilterPatternContextPathTest {
    private static final String SPEC_NAME = "CspFilterPatternContextPathTest";

    @ParameterizedTest(name = "context path \"{0}\"")
    @ValueSource(strings = {"", "/app", "/app/"})
    void narrowedPatternAppliesTheHeaderAndNonceToMatchingRequestsOnly(String contextPath) {
        Map<String, Object> properties = new HashMap<>();
        properties.put("spec.name", SPEC_NAME);
        properties.put("micronaut.security.csp.filter.pattern", "/foo/**");
        properties.put("micronaut.security.csp.script-src.nonce", true);
        if (!contextPath.isEmpty()) {
            properties.put("micronaut.server.context-path", contextPath);
        }
        String prefix = contextPath.endsWith("/") ? contextPath.substring(0, contextPath.length() - 1) : contextPath;
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties);
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            BlockingHttpClient client = httpClient.toBlocking();

            HttpResponse<String> matching = client.exchange(HttpRequest.GET(prefix + "/foo/page"), String.class);
            ContentSecurityPolicy policy = ContentSecurityPolicy.of(matching);
            assertNotNull(policy, "a request matching filter.pattern must receive the CSP header");
            assertEquals("'nonce-" + matching.body() + "'", policy.scriptSrc().value(), "header and request nonce must agree");

            HttpResponse<String> other = client.exchange(HttpRequest.GET(prefix + "/bar/page"), String.class);
            assertNull(ContentSecurityPolicy.of(other), "a request outside filter.pattern must not receive the CSP header");
            assertEquals("no nonce", other.body());
        }
    }

    @ParameterizedTest(name = "pattern \"{0}\"")
    @ValueSource(strings = {"", "   "})
    void emptyOrBlankPatternFailsStartupInsteadOfSilentlyDisablingThePolicy(String pattern) {
        BeanInstantiationException exception = assertThrows(BeanInstantiationException.class,
            () -> ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.filter.pattern", pattern,
                "micronaut.security.csp.script-src.nonce", true)).close());

        assertTrue(exception.getMessage().contains("pattern - must not be blank"), exception::getMessage);
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller
    static class PatternController {
        @Get("/foo/page")
        @Produces(MediaType.TEXT_PLAIN)
        String foo(HttpRequest<?> request) {
            return nonce(request);
        }

        @Get("/bar/page")
        @Produces(MediaType.TEXT_PLAIN)
        String bar(HttpRequest<?> request) {
            return nonce(request);
        }

        private static String nonce(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class).orElse("no nonce");
        }
    }
}
