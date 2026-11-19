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
package io.micronaut.security.cspdisabled;

import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.context.BeanContext;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.nonce.ContentSecurityPolicyNonceGenerator;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

@Property(name = "micronaut.security.csp.enabled", value = StringUtils.FALSE)
@Property(name = "micronaut.security.csp.script-src.nonce", value = StringUtils.TRUE)
@Property(name = "spec.name", value = "CspDisabledTest")
@MicronautTest
class CspDisabledTest {
    @Inject
    BeanContext beanContext;

    @Test
    void disablingTheModuleRemovesFiltersAndHeader(@Client("/") HttpClient httpClient) {
        assertFalse(beanContext.containsBean(ContentSecurityPolicyGenerator.class));

        HttpResponse<String> response = httpClient.toBlocking().exchange(HttpRequest.GET("/csp-disabled"), String.class);

        assertNull(ContentSecurityPolicy.of(response));
        assertNull(ContentSecurityPolicy.of(response.getHeaders(), ContentSecurityPolicy.CONTENT_SECURITY_POLICY_REPORT_ONLY));
        assertEquals("no nonce", response.body());
    }

    @Requires(property = "spec.name", value = "CspDisabledTest")
    @Controller("/csp-disabled")
    static class CspDisabledController {
        @Get
        @Produces(MediaType.TEXT_PLAIN)
        String index(HttpRequest<?> request) {
            return request.getAttribute(ContentSecurityPolicyNonceGenerator.CSP_NONCE_ATTRIBUTE, String.class)
                .orElse("no nonce");
        }
    }
}
