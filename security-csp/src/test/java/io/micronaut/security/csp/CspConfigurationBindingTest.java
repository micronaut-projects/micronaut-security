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
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.BASE_URI;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.FENCED_FRAME_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.IMG_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.OBJECT_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.PREFETCH_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.REPORT_TO;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.SCRIPT_SRC;
import static io.micronaut.security.csp.ContentSecurityPolicyGenerator.STYLE_SRC;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Binds directive settings from configuration and verifies the policy the default generator builds from them.
 */
class CspConfigurationBindingTest {

    static Stream<Arguments> singleDirectiveSettings() {
        String hash = "'sha256-Eco45CPSfPGYCeRWuzpCqnc/toI8+r22Lkjfm5XoezE='";
        return Stream.of(
            Arguments.of("base-uri defaults to 'none'", Map.of(), BASE_URI, "'none'"),
            Arguments.of("object-src defaults to 'none'", Map.of(), OBJECT_SRC, "'none'"),
            Arguments.of("script-src defaults to 'none'", Map.of(), SCRIPT_SRC, "'none'"),
            Arguments.of("fenced-frame-src is omitted by default", Map.of(), FENCED_FRAME_SRC, null),
            Arguments.of("prefetch-src is omitted by default", Map.of(), PREFETCH_SRC, null),
            Arguments.of("report-to is omitted by default", Map.of(), REPORT_TO, null),
            Arguments.of("script-src http", Map.of("micronaut.security.csp.script-src.http", true), SCRIPT_SRC, "http:"),
            Arguments.of("script-src https", Map.of("micronaut.security.csp.script-src.https", true), SCRIPT_SRC, "https:"),
            Arguments.of("script-src self", Map.of("micronaut.security.csp.script-src.self", true), SCRIPT_SRC, "'self'"),
            Arguments.of("script-src unsafe-eval", Map.of("micronaut.security.csp.script-src.unsafe-eval", true), SCRIPT_SRC, "'unsafe-eval'"),
            Arguments.of("script-src unsafe-inline", Map.of("micronaut.security.csp.script-src.unsafe-inline", true), SCRIPT_SRC, "'unsafe-inline'"),
            Arguments.of("script-src self and hash", Map.of(
                "micronaut.security.csp.script-src.self", true,
                "micronaut.security.csp.script-src.values", List.of(hash)), SCRIPT_SRC, "'self' " + hash),
            Arguments.of("script-src self, hash and URL in configured order", Map.of(
                "micronaut.security.csp.script-src.self", true,
                "micronaut.security.csp.script-src.values", List.of(hash, "https://cdn.jsdelivr.net")), SCRIPT_SRC, "'self' " + hash + " https://cdn.jsdelivr.net"),
            Arguments.of("style-src self and URL", Map.of(
                "micronaut.security.csp.style-src.self", true,
                "micronaut.security.csp.style-src.values", List.of("https://cdn.jsdelivr.net")), STYLE_SRC, "'self' https://cdn.jsdelivr.net"),
            Arguments.of("img-src scheme sources are unquoted", Map.of(
                "micronaut.security.csp.img-src.data", true,
                "micronaut.security.csp.img-src.https", true), IMG_SRC, "https: data:"),
            Arguments.of("fenced-frame-src can be enabled", Map.of("micronaut.security.csp.fenced-frame-src.enabled", true), FENCED_FRAME_SRC, "'none'"),
            Arguments.of("disabled directive is omitted", Map.of("micronaut.security.csp.img-src.enabled", false), IMG_SRC, null)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("singleDirectiveSettings")
    void bindsASingleDirectiveSetting(String description, Map<String, Object> properties, String directive, @Nullable String expectedValue) {
        ContentSecurityPolicy policy = policy(properties);

        ContentSecurityPolicyDirective actual = policy.directives().stream()
            .filter(d -> d.name().equals(directive))
            .findFirst()
            .orElse(null);
        assertEquals(expectedValue == null ? null : new ContentSecurityPolicyDirective(directive, expectedValue), actual, description);
    }

    @Test
    void scriptSrcKeywordSourcesAreBoundAndEmittedInOrder() {
        ContentSecurityPolicy policy = policy(Map.<String, Object>ofEntries(
            Map.entry("micronaut.security.csp.script-src.self", true),
            Map.entry("micronaut.security.csp.script-src.unsafe-inline", true),
            Map.entry("micronaut.security.csp.script-src.unsafe-eval", true),
            Map.entry("micronaut.security.csp.script-src.strict-dynamic", true),
            Map.entry("micronaut.security.csp.script-src.unsafe-hashes", true),
            Map.entry("micronaut.security.csp.script-src.report-sample", true),
            Map.entry("micronaut.security.csp.script-src.wasm-unsafe-eval", true),
            Map.entry("micronaut.security.csp.script-src.trusted-types-eval", true),
            Map.entry("micronaut.security.csp.script-src.report-sha256", true),
            Map.entry("micronaut.security.csp.script-src.report-sha384", true),
            Map.entry("micronaut.security.csp.script-src.report-sha512", true),
            Map.entry("micronaut.security.csp.script-src.values", List.of("https://cdn.example.com"))));

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC,
                "'self' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' 'unsafe-hashes' 'report-sample' "
                    + "'wasm-unsafe-eval' 'trusted-types-eval' 'report-sha256' 'report-sha384' 'report-sha512' https://cdn.example.com"),
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

    @Test
    void guideStarterConfigurationGeneratesTheDocumentedHeader() {
        ContentSecurityPolicy policy = policy(Map.of(
            "micronaut.security.csp.script-src.self", true,
            "micronaut.security.csp.script-src.nonce", true,
            "micronaut.security.csp.style-src.self", true,
            "micronaut.security.csp.img-src.self", true,
            "micronaut.security.csp.font-src.self", true,
            "micronaut.security.csp.connect-src.self", true));

        assertEquals("base-uri 'none'; default-src 'none'; connect-src 'self'; font-src 'self'; object-src 'none'; "
                + "require-trusted-types-for 'script'; frame-ancestors 'none'; frame-src 'none'; img-src 'self'; "
                + "manifest-src 'none'; media-src 'none'; form-action 'self'; worker-src 'none'; style-src 'self'; "
                + "script-src 'nonce-requestnonce' 'self'",
            policy.toString());
    }

    private static ContentSecurityPolicy policy(Map<String, Object> properties) {
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            MutableHttpRequest<?> request = HttpRequest.GET("/");
            request.setAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, "requestnonce");
            ContentSecurityPolicy policy = context.getBean(ContentSecurityPolicyGenerator.class)
                .contentSecurityPolicy(request);
            assertNotNull(policy);
            return policy;
        }
    }
}
