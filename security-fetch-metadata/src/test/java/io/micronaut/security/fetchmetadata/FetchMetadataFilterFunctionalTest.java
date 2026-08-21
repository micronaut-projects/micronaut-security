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
package io.micronaut.security.fetchmetadata;

import io.micronaut.context.annotation.Property;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.Mode;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.Site;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.fetchmetadata.rules.FetchMetadataRulesConfigurationProperties;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Property(name = FetchMetadataRulesConfigurationProperties.PROPERTY_ALLOW_NO_FETCH_METADATA,
    value = StringUtils.FALSE)
@MicronautTest
class FetchMetadataFilterFunctionalTest {

    @Inject
    @Client("/")
    HttpClient httpClient;

    BlockingHttpClient client;

    @Test
    void allowsSameOriginRequests() {
        HttpResponse<String> response = exchange(request(HttpMethod.POST, Site.SAME_ORIGIN,
            Mode.CORS, Destination.EMPTY));

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void allowsRequestsInitiatedThroughBrowserUi() {
        HttpResponse<String> response = exchange(request(HttpMethod.GET, Site.NONE,
            Mode.NAVIGATE, Destination.DOCUMENT));

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void allowsSimpleCrossSiteNavigations() {
        HttpResponse<String> response = exchange(request(HttpMethod.GET, Site.CROSS_SITE,
            Mode.NAVIGATE, Destination.DOCUMENT));

        assertEquals(HttpStatus.OK, response.getStatus());
    }

    @Test
    void allowsCrossSiteRequestsWhenTheRouteCorsConfigurationAllowsTheOrigin() {
        MutableHttpRequest<?> request = request(HttpMethod.GET, "/fetch-metadata/cors",
            Site.CROSS_SITE, Mode.CORS, Destination.EMPTY)
            .header(HttpHeaders.ORIGIN, "https://allowed.example");

        HttpResponse<String> response = exchange(request);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("https://allowed.example",
            response.getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    @Test
    void allowsCorsPreflightWhenTheRequestedMethodIsAllowed() {
        MutableHttpRequest<?> request = request(HttpMethod.OPTIONS, "/fetch-metadata/cors-post",
            Site.CROSS_SITE, Mode.CORS, Destination.EMPTY)
            .header(HttpHeaders.ORIGIN, "https://allowed.example")
            .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name());

        HttpResponse<String> response = exchange(request);

        assertEquals(HttpStatus.OK, response.getStatus());
        assertEquals("https://allowed.example",
            response.getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
        assertEquals(HttpMethod.POST.name(),
            response.getHeaders().get(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS));
    }

    @Test
    void rejectsCrossSiteRequestsWhenTheRouteCorsConfigurationRejectsTheOrigin() {
        MutableHttpRequest<?> request = request(HttpMethod.GET, "/fetch-metadata/cors",
            Site.CROSS_SITE, Mode.CORS, Destination.EMPTY)
            .header(HttpHeaders.ORIGIN, "https://disallowed.example");

        assertForbidden(request);
    }

    @Test
    void originHeaderDoesNotExemptARouteWithoutCorsConfiguration() {
        MutableHttpRequest<?> request = request(HttpMethod.GET, Site.CROSS_SITE,
            Mode.CORS, Destination.EMPTY)
            .header(HttpHeaders.ORIGIN, "https://allowed.example");

        assertForbidden(request);
    }

    @Test
    void corsRouteExemptionRequiresAnOriginHeader() {
        assertForbidden(request(HttpMethod.GET, "/fetch-metadata/cors",
            Site.CROSS_SITE, Mode.CORS, Destination.EMPTY));
    }

    @Test
    void rejectsCrossSiteNonNavigationRequests() {
        assertForbidden(request(HttpMethod.GET, Site.CROSS_SITE, Mode.NO_CORS, Destination.IMAGE));
    }

    @Test
    void rejectsUnsafeCrossSiteNavigations() {
        assertForbidden(request(HttpMethod.POST, Site.CROSS_SITE, Mode.NAVIGATE,
            Destination.DOCUMENT));
    }

    @Test
    void rejectsObjectAndEmbedNavigations() {
        assertForbidden(request(HttpMethod.GET, Site.CROSS_SITE, Mode.NAVIGATE,
            Destination.OBJECT));
        assertForbidden(request(HttpMethod.GET, Site.CROSS_SITE, Mode.NAVIGATE,
            Destination.EMBED));
    }

    @Test
    void rejectsSameSiteRequestsByDefault() {
        assertForbidden(request(HttpMethod.GET, Site.SAME_SITE, Mode.NO_CORS, Destination.IMAGE));
    }

    @Test
    void rejectsRequestsWithoutFetchMetadataWhenCompatibilityRuleIsDisabled() {
        assertForbidden(HttpRequest.GET("/fetch-metadata"));
    }

    @Test
    void rejectsIncompleteFetchMetadataWhenCompatibilityRuleIsDisabled() {
        assertForbidden(HttpRequest.GET("/fetch-metadata")
            .header(HttpHeaders.SEC_FETCH_SITE, Site.SAME_ORIGIN.toString()));
    }

    private HttpResponse<String> exchange(HttpRequest<?> request) {
        if (client == null) {
            client = httpClient.toBlocking();
        }
        return client.exchange(request, String.class);
    }

    private void assertForbidden(HttpRequest<?> request) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> exchange(request));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    private static MutableHttpRequest<?> request(HttpMethod method,
                                                  Site site,
                                                  Mode mode,
                                                  Destination destination) {
        return request(method, "/fetch-metadata", site, mode, destination);
    }

    private static MutableHttpRequest<?> request(HttpMethod method,
                                                  String path,
                                                  Site site,
                                                  Mode mode,
                                                  Destination destination) {
        return HttpRequest.create(method, path)
            .header(HttpHeaders.SEC_FETCH_SITE, site.toString())
            .header(HttpHeaders.SEC_FETCH_MODE, mode.toString())
            .header(HttpHeaders.SEC_FETCH_DEST, destination.toString());
    }
}
