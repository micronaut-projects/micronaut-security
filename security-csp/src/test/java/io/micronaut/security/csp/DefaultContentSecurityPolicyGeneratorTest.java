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

import io.micronaut.http.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultContentSecurityPolicyGeneratorTest {

    @Test
    void generatesSecureDefaultPolicy() {
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(
                new ContentSecurityPolicyConfigurationProperties(), request -> "unused");

        assertEquals(List.of(
                new CspDirective(ContentSecurityPolicyGenerator.BASE_URI, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.FONT_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.PREFETCH_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
                new CspDirective(ContentSecurityPolicyGenerator.FRAME_ANCESTORS, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.FRAME_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.MANIFEST_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.MEDIA_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.FORM_ACTION, "'self'"),
                new CspDirective(ContentSecurityPolicyGenerator.STYLE_SRC, "'none'"),
                new CspDirective(ContentSecurityPolicyGenerator.WORKER_SRC, "'none'")
        ), generator.contentSecurityPolicy());
    }

    @Test
    void excludesDisabledDirectives() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setBaseUriEnabled(false);
        configuration.setConnectSrcEnabled(false);
        configuration.setFencedFrameSrcEnabled(false);
        configuration.setFontSrcEnabled(false);
        configuration.setObjectSrcEnabled(false);
        configuration.setPrefetchSrcEnabled(false);
        configuration.setReportUriEnabled(false);
        configuration.setRequireTrustedTypesForEnabled(false);
        configuration.setFrameAncestorsEnabled(false);
        configuration.setFrameSrcEnabled(false);
        configuration.setImgSrcEnabled(false);
        configuration.setManifestSrcEnabled(false);
        configuration.setMediaSrcEnabled(false);
        configuration.setFormActionEnabled(false);
        configuration.setStyleSrcEnabled(false);
        configuration.setWorkerSrcEnabled(false);

        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, request -> "unused");

        assertEquals(List.of(), generator.contentSecurityPolicy());
    }

    @Test
    void joinsConfiguredSourceExpressions() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setConnectSrc(List.of("'self'", "https://api.example.com"));

        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, request -> "unused");

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'self' https://api.example.com"),
                generator.contentSecurityPolicy().get(1));
    }

    @Test
    void invokesOverriddenDirectiveMethod() {
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(
                new ContentSecurityPolicyConfigurationProperties(), request -> "unused") {
            @Override
            protected CspDirective connectSrc() {
                return new CspDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com");
            }
        };

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com"),
                generator.contentSecurityPolicy().get(1));
    }

    @Test
    void addsRequestNonceToScriptSource() {
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(
                new ContentSecurityPolicyConfigurationProperties(), currentRequest -> "nonce");

        List<CspDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsStrictDynamicToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcStrictDynamic(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, currentRequest -> "nonce");

        List<CspDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'strict-dynamic'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnsafeEvalToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcUnsafeEval(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, currentRequest -> "nonce");

        List<CspDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'unsafe-eval'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnquotedHttpAndHttpsSchemeSourcesWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcHttp(true);
        configuration.setScriptSrcHttps(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, currentRequest -> "nonce");

        List<CspDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new CspDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' http: https:"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsReportUriWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        configuration.setReportUri(List.of("https://example.com/csp-reports"));

        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, request -> "unused");

        assertTrue(generator.contentSecurityPolicy().contains(
                new CspDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp-reports")));
    }
}
