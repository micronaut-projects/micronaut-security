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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Keeps the example of the "Migrating from Micronaut Views" guide section true.
 */
class ViewsMigrationExampleTest {

    @Test
    void theDocumentedConfigurationGeneratesTheDocumentedPolicy() {
        Map<String, Object> properties = new HashMap<>();
        properties.put("micronaut.security.csp.default-src.self", true);
        properties.put("micronaut.security.csp.img-src.self", true);
        properties.put("micronaut.security.csp.img-src.data", true);
        for (String directive : List.of("script-src", "style-src", "connect-src", "font-src", "frame-src", "media-src",
            "manifest-src", "worker-src", "object-src")) {
            properties.put("micronaut.security.csp." + directive + ".enabled", false);
        }
        try (ApplicationContext context = ApplicationContext.run(properties)) {
            ContentSecurityPolicy policy = context.getBean(ContentSecurityPolicyGenerator.class).contentSecurityPolicy(HttpRequest.GET("/"));

            assertEquals("base-uri 'none'; default-src 'self'; require-trusted-types-for 'script'; frame-ancestors 'none'; "
                + "img-src 'self' data:; form-action 'self'", policy.toHeaderValue());
        }
    }
}
