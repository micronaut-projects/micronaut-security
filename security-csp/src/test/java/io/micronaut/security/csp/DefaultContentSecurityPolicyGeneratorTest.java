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
        ContentSecurityPolicyConfiguration cfg = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(
            cfg, new DefaultScriptSrcGenerator(cfg, request -> "unused"));

        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.BASE_URI, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FONT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.PREFETCH_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_ANCESTORS, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MANIFEST_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MEDIA_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FORM_ACTION, "'self'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.STYLE_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.WORKER_SRC, "'none'")
        ), generator.contentSecurityPolicy());
    }

    @Test
    void excludesDisabledDirectives() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setBaseUriEnabled(false);
        configuration.setDefaultSrcEnabled(false);
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

        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, request -> "unused"));

        assertEquals(List.of(), generator.contentSecurityPolicy());
    }

    @Test
    void joinsConfiguredSourceExpressions() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setConnectSrc(List.of("'self'", "https://api.example.com"));

        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, request -> "unused"));

        assertTrue(generator.contentSecurityPolicy().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'self' https://api.example.com")));
    }

    @Test
    void invokesOverriddenDirectiveMethod() {
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, request -> "unused")) {
            @Override
            protected ContentSecurityPolicyDirective connectSrc() {
                return new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com");
            }
        };

        assertTrue(generator.contentSecurityPolicy().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com")));
    }

    @Test
    void addsRequestNonceToScriptSource() {
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, req -> "nonce"));

        List<ContentSecurityPolicyDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsStrictDynamicToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcStrictDynamic(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, currentRequest -> "nonce"));

        List<ContentSecurityPolicyDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'strict-dynamic'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnsafeEvalToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcUnsafeEval(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, currentRequest -> "nonce"));

        List<ContentSecurityPolicyDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'unsafe-eval'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnquotedHttpAndHttpsSchemeSourcesWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setScriptSrcHttp(true);
        configuration.setScriptSrcHttps(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, currentRequest -> "nonce"));
        List<ContentSecurityPolicyDirective> directives = generator.contentSecurityPolicy(request);

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' http: https:"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsReportUriWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        configuration.setReportUri(List.of("https://example.com/csp-reports"));
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration, new DefaultScriptSrcGenerator(configuration, currentRequest -> "nonce"));

        assertTrue(generator.contentSecurityPolicy().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp-reports")));
    }
}
