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
package io.micronaut.security.csp.filters;

import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import io.micronaut.security.csp.conf.scriptSrc.ScriptSrcConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ContentSecurityPolicyFilterTest {

    @Test
    void addsContentSecurityPolicyHeader() {
        ContentSecurityPolicyFilter filter = new ContentSecurityPolicyFilter(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'self' images.example.com"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null)
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                new ScriptSrcConfigurationProperties(),
                request -> "unused"
        );
        HttpRequest<?> request = HttpRequest.GET("/");
        MutableHttpResponse<?> response = HttpResponse.ok();

        filter.filter(request, response);

        assertEquals("default-src 'self'; img-src 'self' images.example.com; upgrade-insecure-requests",
                response.header("Content-Security-Policy"));
    }

    @Test
    void omitsContentSecurityPolicyHeaderWhenGeneratorReturnsNull() {
        ContentSecurityPolicyFilter filter = new ContentSecurityPolicyFilter(
                request -> null,
                new ContentSecurityPolicyConfigurationProperties(),
                new ScriptSrcConfigurationProperties(),
                request -> "unused"
        );
        HttpRequest<?> request = HttpRequest.GET("/");
        MutableHttpResponse<?> response = HttpResponse.ok();

        filter.filter(request, response);

        assertNull(response.header(ContentSecurityPolicy.CONTENT_SECURITY_POLICY));
    }
}
