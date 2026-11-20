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
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.server.filter.ResponseHeaderPopulator;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import jakarta.inject.Singleton;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that {@code micronaut.security.csp.enabled=false} also turns off the filter package when
 * the application registers its own policy and nonce generators. The test lives outside
 * {@code io.micronaut.security.csp} so that the package-level requirements of the module do not
 * disable the application beans themselves.
 */
class CspDisabledWithCustomGeneratorsTest {
    private static final String SPEC_NAME = "CspDisabledWithCustomGeneratorsTest";

    @Test
    void disablingTheModuleRemovesTheFiltersEvenWithCustomGenerators() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of(
                "spec.name", SPEC_NAME,
                "micronaut.security.csp.enabled", false,
                "micronaut.security.csp.script-src.nonce", true));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            ApplicationContext context = server.getApplicationContext();
            assertTrue(context.getBean(ContentSecurityPolicyGenerator.class) instanceof SelfOnlyGenerator);
            assertTrue(context.getBean(ContentSecurityPolicyNonceGenerator.class) instanceof FixedNonceGenerator);
            assertTrue(context.getBeansOfType(ResponseHeaderPopulator.class).stream()
                    .noneMatch(populator -> populator.getClass().getPackageName().startsWith("io.micronaut.security.csp")),
                "no CSP response header populator must be registered when the module is disabled");

            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-disabled-custom"), String.class);

            assertNull(ContentSecurityPolicy.of(response));
            assertNull(ContentSecurityPolicy.of(response.getHeaders(), HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY));
            assertEquals("no nonce", response.body());
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class SelfOnlyGenerator implements ContentSecurityPolicyGenerator {
        @Override
        public ContentSecurityPolicy contentSecurityPolicy(HttpRequest<?> request) {
            return new ContentSecurityPolicy(List.of(new ContentSecurityPolicyDirective(DEFAULT_SRC, QUOTED_SELF)));
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Singleton
    static class FixedNonceGenerator implements ContentSecurityPolicyNonceGenerator {
        @Override
        public String generateNonce(HttpRequest<?> request) {
            return "fixed";
        }
    }

    @Requires(property = "spec.name", value = SPEC_NAME)
    @Controller("/csp-disabled-custom")
    static class CspDisabledCustomController {
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class)
                .orElse("no nonce");
        }
    }
}
