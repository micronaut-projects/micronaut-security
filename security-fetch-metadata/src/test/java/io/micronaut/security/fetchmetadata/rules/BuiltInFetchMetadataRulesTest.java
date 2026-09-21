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
package io.micronaut.security.fetchmetadata.rules;

import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.Mode;
import io.micronaut.http.SecFetch;
import io.micronaut.http.Site;
import io.micronaut.security.fetchmetadata.FetchMetadataRuleResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BuiltInFetchMetadataRulesTest {

    private static final HttpRequest<?> GET = HttpRequest.GET("/");
    private static final HttpRequest<?> POST = HttpRequest.POST("/", "");

    @Test
    void browserInitiatedRuleAllowsOnlySiteNone() {
        BrowserInitiatedRequestFetchMetadataRule rule =
            new BrowserInitiatedRequestFetchMetadataRule();

        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(GET, secFetch(Site.NONE)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.SAME_ORIGIN)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN, rule.check(GET, null));
    }

    @Test
    void sameOriginRuleAllowsOnlySameOrigin() {
        SameOriginFetchMetadataRule rule = new SameOriginFetchMetadataRule();

        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(GET, secFetch(Site.SAME_ORIGIN)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.SAME_SITE)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN, rule.check(GET, null));
    }

    @Test
    void sameSiteRuleAllowsOnlySameSite() {
        SameSiteFetchMetadataRule rule = new SameSiteFetchMetadataRule();

        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(GET, secFetch(Site.SAME_SITE)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.CROSS_SITE)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN, rule.check(GET, null));
    }

    @Test
    void noMetadataRuleAllowsOnlyRequestsWithoutSiteHeader() {
        NoFetchMetadataRule rule = new NoFetchMetadataRule();
        HttpRequest<?> requestWithSite = HttpRequest.GET("/")
            .header(HttpHeaders.SEC_FETCH_SITE, Site.CROSS_SITE.toString());

        assertEquals(FetchMetadataRuleResult.ALLOWED, rule.check(GET, null));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(requestWithSite, null));
    }

    @Test
    void navigationRuleAllowsSimpleGetNavigations() {
        SimpleTopLevelNavigationAndIframingFetchMetadataRule rule =
            new SimpleTopLevelNavigationAndIframingFetchMetadataRule();

        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(GET, secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.DOCUMENT)));
        assertEquals(FetchMetadataRuleResult.ALLOWED,
            rule.check(GET, secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.IFRAME)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(POST, secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.DOCUMENT)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.CROSS_SITE, Mode.NO_CORS, Destination.IMAGE)));
    }

    @Test
    void navigationRuleRejectsPluginDestinationsAndCannotDecideWithoutMetadata() {
        SimpleTopLevelNavigationAndIframingFetchMetadataRule rule =
            new SimpleTopLevelNavigationAndIframingFetchMetadataRule();

        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.OBJECT)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN,
            rule.check(GET, secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.EMBED)));
        assertEquals(FetchMetadataRuleResult.UNKNOWN, rule.check(GET, null));
    }

    private static SecFetch secFetch(Site site) {
        return secFetch(site, Mode.NO_CORS, Destination.IMAGE);
    }

    private static SecFetch secFetch(Site site, Mode mode, Destination destination) {
        return new SecFetch(site, mode, destination, false);
    }
}
