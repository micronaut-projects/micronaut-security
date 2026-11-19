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
import io.micronaut.http.client.HttpClient;
import io.micronaut.runtime.server.EmbeddedServer;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfiguration;
import io.micronaut.security.csp.conf.baseuri.BaseUriConfiguration;
import io.micronaut.security.csp.conf.defaultsrc.DefaultSrcConfiguration;
import io.micronaut.security.csp.conf.connectsrc.ConnectSrcConfiguration;
import io.micronaut.security.csp.conf.fencedframesrc.FencedFrameSrcConfiguration;
import io.micronaut.security.csp.conf.fontsrc.FontSrcConfiguration;
import io.micronaut.security.csp.conf.objectsrc.ObjectSrcConfiguration;
import io.micronaut.security.csp.conf.prefetchsrc.PrefetchSrcConfiguration;
import io.micronaut.security.csp.conf.reportto.ReportToConfiguration;
import io.micronaut.security.csp.conf.scriptsrc.ScriptSrcConfiguration;
import io.micronaut.security.csp.conf.frameancestors.FrameAncestorsConfiguration;
import io.micronaut.security.csp.conf.framesrc.FrameSrcConfiguration;
import io.micronaut.security.csp.conf.imgsrc.ImgSrcConfiguration;
import io.micronaut.security.csp.conf.manifestsrc.ManifestSrcConfiguration;
import io.micronaut.security.csp.conf.mediasrc.MediaSrcConfiguration;
import io.micronaut.security.csp.conf.formaction.FormActionConfiguration;
import io.micronaut.security.csp.conf.stylesrc.StyleSrcConfiguration;
import io.micronaut.security.csp.conf.workersrc.WorkerSrcConfiguration;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * Verifies the two documented ways of customizing the policy: subclassing
 * {@link DefaultContentSecurityPolicyGenerator} and replacing the generator bean.
 */
class CustomGeneratorBeanTest {

    @Test
    void subclassBeanReplacesTheDefaultGenerator() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "SubclassGenerator",
                "micronaut.security.csp.script-src.self", true));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertInstanceOf(ImgSrcSelfGenerator.class, server.getApplicationContext().getBean(ContentSecurityPolicyGenerator.class));

            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/custom-generator"), String.class);
            ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);

            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'self'"), policy.imgSrc());
            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"), policy.defaultSrc());
            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.SCRIPT_SRC, "'self'"), policy.scriptSrc(),
                "directive configuration must keep applying to a subclass bean");
        }
    }

    @Test
    void customGeneratorBeanReplacesTheDefaultGenerator() {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "CustomGenerator"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/custom-generator"), String.class);

            assertEquals("default-src 'self'", response.header(ContentSecurityPolicy.CONTENT_SECURITY_POLICY));
        }
    }

    @Requires(property = "spec.name", value = "SubclassGenerator")
    @Singleton
    static class ImgSrcSelfGenerator extends DefaultContentSecurityPolicyGenerator {
        @SuppressWarnings("ParameterNumber")
        ImgSrcSelfGenerator(ContentSecurityPolicyConfiguration cspConfiguration,
                            BaseUriConfiguration baseUri,
                            DefaultSrcConfiguration defaultSrc,
                            ConnectSrcConfiguration connectSrc,
                            FencedFrameSrcConfiguration fencedFrameSrc,
                            FontSrcConfiguration fontSrc,
                            ObjectSrcConfiguration objectSrc,
                            PrefetchSrcConfiguration prefetchSrc,
                            ReportToConfiguration reportTo,
                            ScriptSrcConfiguration scriptSrc,
                            FrameAncestorsConfiguration frameAncestors,
                            FrameSrcConfiguration frameSrc,
                            ImgSrcConfiguration imgSrc,
                            ManifestSrcConfiguration manifestSrc,
                            MediaSrcConfiguration mediaSrc,
                            FormActionConfiguration formAction,
                            StyleSrcConfiguration styleSrc,
                            WorkerSrcConfiguration workerSrc) {
            super(cspConfiguration, baseUri, defaultSrc, connectSrc, fencedFrameSrc, fontSrc, objectSrc, prefetchSrc, reportTo, scriptSrc, frameAncestors, frameSrc, imgSrc, manifestSrc, mediaSrc, formAction, styleSrc, workerSrc);
        }

        @Override
        protected @Nullable ContentSecurityPolicyDirective imgSrc() {
            return new ContentSecurityPolicyDirective(IMG_SRC, QUOTED_SELF);
        }
    }

    @Requires(property = "spec.name", value = "CustomGenerator")
    @Singleton
    static class SelfOnlyGenerator implements ContentSecurityPolicyGenerator {
        @Override
        public ContentSecurityPolicy contentSecurityPolicy(HttpRequest<?> request) {
            return new ContentSecurityPolicy(List.of(new ContentSecurityPolicyDirective(DEFAULT_SRC, QUOTED_SELF)));
        }
    }

    @Requires(property = "spec.name", pattern = "SubclassGenerator|CustomGenerator")
    @Controller("/custom-generator")
    static class CustomGeneratorController {
        @Get
        String index() {
            return "ok";
        }
    }
}
