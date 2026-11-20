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
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.order.Ordered;
import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.Mode;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.SecFetch;
import io.micronaut.http.Site;
import io.micronaut.http.client.BlockingHttpClient;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Singleton;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Application rule beans are picked up by the filter and run at the position their order gives
 * them relative to the built-in rules (100 to 600).
 */
@Property(name = "spec.name", value = "CustomRuleOrderTest")
@MicronautTest
class CustomRuleOrderTest {

    private static final String VETO = "X-Test-Veto";

    @Test
    void aCustomRuleRunningFirstCanRejectARequestABuiltInRuleWouldAllow(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        assertEquals(HttpStatus.OK, client.exchange(HttpRequest.GET("/fetch-metadata")).getStatus());

        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(HttpRequest.GET("/fetch-metadata/filtered/test")));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    @Test
    void aCustomRuleWithoutAnOrderRunsBeforeEveryBuiltInRule(@Client("/") HttpClient httpClient) {
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> httpClient.toBlocking().exchange(HttpRequest.GET("/fetch-metadata").header(VETO, "default")));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    @Test
    void aCustomRuleRunsBetweenTheBuiltInRulesAroundItsOrder(@Client("/") HttpClient httpClient) {
        BlockingHttpClient client = httpClient.toBlocking();

        // the same-origin rule (200) allows the request before the custom rule (250) can reject it
        assertEquals(HttpStatus.OK, client.exchange(secFetch(Site.SAME_ORIGIN, Mode.CORS, Destination.EMPTY)
            .header(VETO, "between")).getStatus());

        // the custom rule (250) rejects the request before the simple navigation rule (500) can allow it
        HttpClientResponseException exception = assertThrows(HttpClientResponseException.class,
            () -> client.exchange(secFetch(Site.CROSS_SITE, Mode.NAVIGATE, Destination.DOCUMENT).header(VETO, "between")));
        assertEquals(HttpStatus.FORBIDDEN, exception.getStatus());
    }

    private static MutableHttpRequest<?> secFetch(Site site, Mode mode, Destination destination) {
        return HttpRequest.GET("/fetch-metadata")
            .header(HttpHeaders.SEC_FETCH_SITE, site.toString())
            .header(HttpHeaders.SEC_FETCH_MODE, mode.toString())
            .header(HttpHeaders.SEC_FETCH_DEST, destination.toString());
    }

    @Requires(property = "spec.name", value = "CustomRuleOrderTest")
    @Singleton
    static class DefaultOrderRule implements HttpRequestFetchMetadataRule {
        @Override
        public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
            return "default".equals(request.getHeaders().get(VETO))
                ? FetchMetadataRuleResult.REJECTED
                : FetchMetadataRuleResult.UNKNOWN;
        }
    }

    @Requires(property = "spec.name", value = "CustomRuleOrderTest")
    @Singleton
    static class BetweenSameOriginAndSameSiteRule implements HttpRequestFetchMetadataRule {
        @Override
        public FetchMetadataRuleResult check(HttpRequest<?> request, @Nullable SecFetch secFetch) {
            return "between".equals(request.getHeaders().get(VETO))
                ? FetchMetadataRuleResult.REJECTED
                : FetchMetadataRuleResult.UNKNOWN;
        }

        @Override
        public int getOrder() {
            return 250;
        }
    }

    @Requires(property = "spec.name", value = "CustomRuleOrderTest")
    @Singleton
    static class RejectFilteredPathRule implements FetchMetadataRule<HttpRequest<?>> {
        @Override
        public FetchMetadataRuleResult check(HttpRequest<?> request) {
            return request.getPath().startsWith("/fetch-metadata/filtered")
                ? FetchMetadataRuleResult.REJECTED
                : FetchMetadataRuleResult.UNKNOWN;
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }
}
