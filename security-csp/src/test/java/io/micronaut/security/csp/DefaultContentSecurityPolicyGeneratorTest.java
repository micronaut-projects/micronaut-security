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
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.baseUri.BaseUriConfigurationProperties;
import io.micronaut.security.csp.conf.connectSrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.connectSrc.ConnectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.defaultSrc.DefaultSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fencedFrameSrc.FencedFrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.fontSrc.FontSrcConfigurationProperties;
import io.micronaut.security.csp.conf.formAction.FormActionConfigurationProperties;
import io.micronaut.security.csp.conf.frameAncestors.FrameAncestorsConfigurationProperties;
import io.micronaut.security.csp.conf.frameSrc.FrameSrcConfigurationProperties;
import io.micronaut.security.csp.conf.imgSrc.ImgSrcConfigurationProperties;
import io.micronaut.security.csp.conf.manifestSrc.ManifestSrcConfigurationProperties;
import io.micronaut.security.csp.conf.mediaSrc.MediaSrcConfigurationProperties;
import io.micronaut.security.csp.conf.objectSrc.ObjectSrcConfigurationProperties;
import io.micronaut.security.csp.conf.prefetchSrc.PrefetchSrcConfigurationProperties;
import io.micronaut.security.csp.conf.reportTo.ReportToConfigurationProperties;
import io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfigurationProperties;
import io.micronaut.security.csp.conf.styleSrc.StyleSrcConfigurationProperties;
import io.micronaut.security.csp.conf.workerSrc.WorkerSrcConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.LinkedHashSet;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultContentSecurityPolicyGeneratorTest {

    @Test
    void generatesSecureDefaultPolicy() {
        ContentSecurityPolicyConfiguration cfg = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(cfg);

        assertEquals(List.of(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.BASE_URI, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FONT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.OBJECT_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REQUIRE_TRUSTED_TYPES_FOR, "'script'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_ANCESTORS, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FRAME_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MANIFEST_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.MEDIA_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.FORM_ACTION, "'self'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.WORKER_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.STYLE_SRC, "'none'"),
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'none'")
        ), policy(generator).directives());
    }

    @Test
    void joinsConfiguredSourceExpressions() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ConnectSrcConfigurationProperties connectSrcConfiguration = new ConnectSrcConfigurationProperties();
        connectSrcConfiguration.setValues(new LinkedHashSet<>(List.of("'self'", "https://api.example.com")));

        ContentSecurityPolicyGenerator generator = generator(configuration, request -> "unused",
            new ScriptSrcConfigurationProperties(), connectSrcConfiguration);

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "'self' https://api.example.com")));
    }

    @Test
    void invokesOverriddenDirectiveMethod() {
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration) {
            @Override
            protected ContentSecurityPolicyDirective connectSrc() {
                return new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com");
            }
        };

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.CONNECT_SRC, "https://api.example.com")));
    }

    @Test
    void addsRequestNonceToScriptSource() {
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyConfiguration configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        ContentSecurityPolicyGenerator generator = generator(configuration, req -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsStrictDynamicToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setNonce(true);
        scriptSrcConfiguration.setStrictDynamic(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'nonce-nonce' 'strict-dynamic'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnsafeEvalToScriptSourceWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setUnsafeEval(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());

        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'unsafe-eval'"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsUnquotedHttpAndHttpsSchemeSourcesWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        ScriptSrcConfigurationProperties scriptSrcConfiguration = new ScriptSrcConfigurationProperties();
        scriptSrcConfiguration.setHttp(true);
        scriptSrcConfiguration.setHttps(true);
        HttpRequest<?> request = HttpRequest.GET("/");
        ContentSecurityPolicyGenerator generator = generator(configuration, currentRequest -> "nonce",
            scriptSrcConfiguration, new ConnectSrcConfigurationProperties());
        List<ContentSecurityPolicyDirective> directives = policy(generator, request).directives();

        assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "http: https:"),
                directives.get(directives.size() - 1));
    }

    @Test
    void addsReportUriWhenEnabled() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportUriEnabled(true);
        configuration.setReportUri(List.of("https://example.com/csp-reports"));
        ContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration);

        assertTrue(policy(generator).directives().contains(
                new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.REPORT_URI, "https://example.com/csp-reports")));
    }

    private static ContentSecurityPolicy policy(ContentSecurityPolicyGenerator generator) {
        return policy(generator, HttpRequest.GET("/"));
    }

    private static ContentSecurityPolicy policy(ContentSecurityPolicyGenerator generator, HttpRequest<?> request) {
        ContentSecurityPolicy policy = generator.contentSecurityPolicy(request);
        assertNotNull(policy);
        return policy;
    }

    private static ContentSecurityPolicyGenerator generator(ContentSecurityPolicyConfiguration configuration,
                                                            Function<HttpRequest<?>, String> nonceProvider,
                                                            ScriptSrcConfigurationProperties scriptSrcConfiguration,
                                                            ConnectSrcConfiguration connectSrcConfiguration) {
        return new DefaultContentSecurityPolicyGenerator(configuration,
            nonceProvider,
            new BaseUriConfigurationProperties(),
            new DefaultSrcConfigurationProperties(),
            connectSrcConfiguration,
            new FencedFrameSrcConfigurationProperties(),
            new FontSrcConfigurationProperties(),
            new ObjectSrcConfigurationProperties(),
            new PrefetchSrcConfigurationProperties(),
            new ReportToConfigurationProperties(),
            scriptSrcConfiguration,
            new FrameAncestorsConfigurationProperties(),
            new FrameSrcConfigurationProperties(),
            new ImgSrcConfigurationProperties(),
            new ManifestSrcConfigurationProperties(),
            new MediaSrcConfigurationProperties(),
            new FormActionConfigurationProperties(),
            new StyleSrcConfigurationProperties(),
            new WorkerSrcConfigurationProperties());
    }
}
