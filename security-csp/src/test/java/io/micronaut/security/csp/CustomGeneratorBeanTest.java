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
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, Map.of("spec.name", "SubclassGenerator"));
             HttpClient httpClient = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            assertInstanceOf(ImgSrcSelfGenerator.class, server.getApplicationContext().getBean(ContentSecurityPolicyGenerator.class));

            HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/custom-generator"), String.class);
            ContentSecurityPolicy policy = ContentSecurityPolicy.of(response);

            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'self'"), policy.imgSrc());
            assertEquals(new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'none'"), policy.defaultSrc());
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
        ImgSrcSelfGenerator(ContentSecurityPolicyConfiguration cspConfiguration) {
            super(cspConfiguration);
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
