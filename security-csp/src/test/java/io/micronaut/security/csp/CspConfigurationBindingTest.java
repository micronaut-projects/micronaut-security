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
import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Binds directive settings from configuration and verifies the policy the default generator builds from them.
 */
class CspConfigurationBindingTest {

    @Test
    void scriptSrcKeywordSourcesAreBoundAndEmittedInOrder() {
        ContentSecurityPolicy policy = policy(Map.of(
            "micronaut.security.csp.script-src.self", true,
            "micronaut.security.csp.script-src.unsafe-inline", true,
            "micronaut.security.csp.script-src.unsafe-eval", true,
            "micronaut.security.csp.script-src.strict-dynamic", true,
            "micronaut.security.csp.script-src.unsafe-hashes", true,
            "micronaut.security.csp.script-src.report-sample", true,
            "micronaut.security.csp.script-src.wasm-unsafe-eval", true,
            "micronaut.security.csp.script-src.trusted-types-eval", true,
            "micronaut.security.csp.script-src.urls", List.of("https://cdn.example.com")));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC,
                "'self' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' 'unsafe-hashes' 'report-sample' "
                    + "'wasm-unsafe-eval' 'trusted-types-eval' https://cdn.example.com"),
            policy.scriptSrc());
    }

    @Test
    void connectSrcSchemeSourcesReplaceTheNoneDefault() {
        ContentSecurityPolicy policy = policy(Map.of(
            "micronaut.security.csp.connect-src.unsafe-webtransport-hashes", true,
            "micronaut.security.csp.connect-src.blob", true,
            "micronaut.security.csp.connect-src.filesystem", true,
            "micronaut.security.csp.connect-src.mediastream", true,
            "micronaut.security.csp.connect-src.ws", true,
            "micronaut.security.csp.connect-src.wss", true));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC,
                "'unsafe-webtransport-hashes' blob: filesystem: mediastream: ws: wss:"),
            policy.connectSrc());
    }

    @Test
    void rootSettingsControlTrustedTypesAndReportUri() {
        ContentSecurityPolicy policy = policy(Map.of(
            "micronaut.security.csp.require-trusted-types-for-enabled", false,
            "micronaut.security.csp.report-uri-enabled", true,
            "micronaut.security.csp.report-uri", List.of("https://example.com/csp")));

        assertNull(policy.requireTrustedTypesFor());
        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp"),
            policy.reportUri());
    }

    @Test
    void requireTrustedTypesForValueIsBound() {
        ContentSecurityPolicy policy = policy(Map.of(
            "micronaut.security.csp.require-trusted-types-for", "'script'"));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
            policy.requireTrustedTypesFor());
    }

    private static ContentSecurityPolicy policy(Map<String, Object> properties) {
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            ContentSecurityPolicy policy = context.getBean(ContentSecurityPolicyGenerator.class)
                .contentSecurityPolicy(HttpRequest.GET("/"));
            assertNotNull(policy);
            return policy;
        }
    }
}
