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
import io.micronaut.security.csp.ContentSecurityPolicy;
import io.micronaut.security.csp.ContentSecurityPolicyDirective;
import io.micronaut.security.csp.ContentSecurityPolicyGenerator;
import io.micronaut.security.csp.conf.ContentSecurityPolicyConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
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
                new ContentSecurityPolicyFilterConfigurationProperties(),
                null
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
                new ContentSecurityPolicyFilterConfigurationProperties(),
                null
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
                new ContentSecurityPolicyFilterConfigurationProperties(),
                null
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/"),
                HttpResponse.ok().header(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'self'")));
    }

    @Test
    void matchesAPatternRelativeToTheServerContextPath() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/foo/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'none'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration,
                () -> "app/"
        );

        assertEquals(List.of(new HttpHeaderEntry(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'none'")),
                populator.findHttpHeaders(HttpRequest.GET("/app/foo/page"), HttpResponse.ok()));
        assertNull(populator.findHttpHeaders(HttpRequest.GET("/app/bar/page"), HttpResponse.ok()));
    }

    @Test
    void keepsAPatternThatAlreadyIncludesTheContextPath() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/app/foo/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'none'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration,
                () -> "/app"
        );

        assertEquals(List.of(new HttpHeaderEntry(HttpHeaders.CONTENT_SECURITY_POLICY, "default-src 'none'")),
                populator.findHttpHeaders(HttpRequest.GET("/app/foo/page"), HttpResponse.ok()));
        assertNull(populator.findHttpHeaders(HttpRequest.GET("/app/app/foo/page"), HttpResponse.ok()));
    }

    @Test
    void omitsContentSecurityPolicyHeaderWhenGeneratorReturnsNull() {
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> null,
                new ContentSecurityPolicyConfigurationProperties(),
                new ContentSecurityPolicyFilterConfigurationProperties(),
                null
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/"), HttpResponse.ok()));
    }

    @Test
    void omitsContentSecurityPolicyHeaderWhenPathDoesNotMatchPattern() {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern("/foo/**");
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
                request -> new ContentSecurityPolicy(List.of(
                        new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'")
                )),
                new ContentSecurityPolicyConfigurationProperties(),
                filterConfiguration,
                null
        );

        assertNull(populator.findHttpHeaders(HttpRequest.GET("/bar"), HttpResponse.ok()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    void rejectsAnEmptyOrBlankPatternThatTheNonceFilterCouldNotMatch(String pattern) {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern(pattern);
        ContentSecurityPolicyConfigurationProperties configuration = new ContentSecurityPolicyConfigurationProperties();

        ConfigurationException exception = assertThrows(ConfigurationException.class,
            () -> new ContentSecurityPolicyResponseHeaderPopulator(request -> null, configuration, filterConfiguration, null));

        assertEquals("micronaut.security.csp.filter.pattern must not be blank", exception.getMessage());
    }

    @ParameterizedTest(name = "pattern {0} matches {1}: {2}")
    @CsvSource({
        "/foo/page, /foo/page, true",
        "/foo/page, /foo/page/, true",
        "/foo/page, /f%6Fo/page, true",
        "/foo/page, /f%6Fo/page/, true",
        "/foo/page, /foo%zzpage, false",
        "/a+b, /a+b, true",
        "/a+b, /a%2Bb, true",
        "/foo/page, /bar/page, false",
        "/, '', true"
    })
    void matchesTheFormsOfThePathThatTheServerMatchesFilterPatternsAgainst(String pattern, String path, boolean matches) {
        assertEquals(matches, ContentSecurityPolicyResponseHeaderPopulator.matchesAnyForm(pattern, path));
    }

    @ParameterizedTest(name = "context path {0}, pattern {1}, request {2}: {3}")
    @CsvSource({
        "/app, /foo/**, /app/foo/page, true",
        "/app/, /foo/**, /app/foo/page, true",
        "app, foo/**, /app/foo/page, true",
        "/app, /foo/**, /foo/page, true",
        "/app, /foo/**, /app/bar/page, false",
        "/app, /, /app, true",
        "/app, /app/foo/**, /app/foo/page, true",
        "/app, /app/foo/**, /foo/page, false",
        "/, /foo/**, /foo/page, true"
    })
    void resolvesThePatternAgainstTheContextPathLikeTheServer(String contextPath, String pattern, String path, boolean header) {
        ContentSecurityPolicyFilterConfigurationProperties filterConfiguration = new ContentSecurityPolicyFilterConfigurationProperties();
        filterConfiguration.setPattern(pattern);
        ContentSecurityPolicyResponseHeaderPopulator populator = new ContentSecurityPolicyResponseHeaderPopulator(
            request -> new ContentSecurityPolicy(List.of(new ContentSecurityPolicyDirective(ContentSecurityPolicyDirectiveNames.DEFAULT_SRC, "'self'"))),
            new ContentSecurityPolicyConfigurationProperties(), filterConfiguration, () -> contextPath);

        assertEquals(header, populator.findHttpHeaders(HttpRequest.GET(path), HttpResponse.ok()) != null);
    }
}
