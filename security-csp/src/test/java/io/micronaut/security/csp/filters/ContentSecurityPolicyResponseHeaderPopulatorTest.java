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

import io.micronaut.context.exceptions.ConfigurationException;
import io.micronaut.http.HttpHeaderEntry;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.security.csp.DefaultContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyDirectiveConfigurations;
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import io.micronaut.security.csp.ContentSecurityPolicyDirectiveNames;

class ContentSecurityPolicyResponseHeaderPopulatorTest {

    @Test
    void addsContentSecurityPolicyHeader() {
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.IMG_SRC, "'self' images.example.com"),
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.UPGRADE_INSECURE_REQUESTS, null)
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                new ContentSecurityPolicyFilterConfigurationProperties()
        );

        assertEquals(
                List.of(new HttpHeaderEntry(HttpHeaders.CONTENT_SECURITY_POLICY,
                        "default-src 'self'; img-src 'self' images.example.com; upgrade-insecure-requests")),
                populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()));
    }

    @Test
    void addsReportOnlyHeaderInReportOnlyMode() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        configuration.setReportOnly(true);
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'none'")
                )),
                configuration,
                new ContentSecurityPolicyFilterConfigurationProperties()
        );

        assertEquals(
                List.of(new HttpHeaderEntry(HttpHeaders.CONTENT_SECURITY_POLICY_REPORT_ONLY, "default-src 'none'")),
                populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()));
    }

    @Test
    void keepsContentSecurityPolicyHeaderAlreadySetByTheResponse() {
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> fail("the generator must not be called when the response already sets the header"),
                new ContentSecurityPolicyConfigurationProperties(),
                new ContentSecurityPolicyFilterConfigurationProperties()
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/"),
                HttpResponse.ok().header(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'")));
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
    void omitsContentSecurityPolicyHeaderForARequestTheFilterDidNotMatch() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/foo/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/foo/page"), HttpResponse.ok()),
                "the filter, not the populator, matches the pattern");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void rejectsAnEmptyOrBlankPatternThatTheNonceFilterCouldNotMatch(String pattern) {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern(pattern);
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();

        ConfigurationException exception = assertThrows(ConfigurationException.class,
            () -> new ContentSecurityPolicyResponseHeaderPopulator(request -> null, configuration, filterConfiguration));

        assertEquals("micronaut.security.csp.filter.pattern must not be blank", exception.getMessage());
    }

    @Test
    void writesTheHeaderForARequestMatchedByTheFilterWhenThePatternIsNarrowed() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/foo/**,/bar/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration
        );
        MutableHttpRequest<?> matched = HttpRequest.GET("/anything");
        matched.setAttribute(ContentSecurityPolicyFilter.MATCHED_ATTRIBUTE, Boolean.TRUE);

        assertEquals(List.of(new HttpHeaderEntry(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'")),
                populator.findHttpHeaders(matched, HttpResponse.ok()));
    }

    @Test
    void keepsTheReportOnlyModeOfThePolicyTheDefaultGeneratorBuilt() {
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();
        DefaultContentSecurityPolicyGenerator generator = new DefaultContentSecurityPolicyGenerator(configuration,
                ContentSecurityPolicyDirectiveConfigurations.builder().build()) { };
        configuration.setReportOnly(true);
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                generator, configuration, new ContentSecurityPolicyFilterConfigurationProperties());

        assertEquals(HttpHeaders.CONTENT_SECURITY_POLICY,
                populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()).iterator().next().name(),
                "until the generator rebuilds its policy, the policy keeps its mode");
    }
}
