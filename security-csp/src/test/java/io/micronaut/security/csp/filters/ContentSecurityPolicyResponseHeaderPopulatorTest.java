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

import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ContentSecurityPolicyResponseHeaderPopulatorTest {

    @Test
    void addsContentSecurityPolicyHeader() {
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.IMG_SRC, "'self' images.example.com"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.UPGRADE_INSECURE_REQUESTS, null)
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                new ContentSecurityPolicyFilterConfigurationProperties()
        );

        assertEquals(
                List.of(new HttpHeaderEntry(ContentSecurityPolicy.CONTENT_SECURITY_POLICY,
                        "default-src 'self'; img-src 'self' images.example.com; upgrade-insecure-requests")),
                populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()));
    }

    @Test
    void omitsContentSecurityPolicyHeaderWhenGeneratorReturnsNull() {
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> null,
                new ContentSecurityPolicyConfigurationProperties(),
                new ContentSecurityPolicyFilterConfigurationProperties()
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()));
    }

    @Test
    void omitsContentSecurityPolicyHeaderWhenPathDoesNotMatchPattern() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/foo/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyGenerator.DEFAULT_SRC, "'self'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/bar"), HttpResponse.ok()));
    }
}
