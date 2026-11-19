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

import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.filter.ServerFilterPhase;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class FetchMetadataFilterTest {

    private static final HttpRequest<?> REQUEST = HttpRequest.GET("/");

    @Test
    void runsBeforeAuthenticationAndAuthorizationFilters() {
        FetchMetadataFilter filter = filterWith(FetchMetadataRuleResult.ALLOWED);

        assertEquals(ServerFilterPhase.SECURITY.before(), filter.getOrder());
    }

    @Test
    void allowsARequestWhenARuleAllowsIt() {
        FetchMetadataFilter filter = filterWith(FetchMetadataRuleResult.ALLOWED);

        assertNull(filter.filterRequest(REQUEST));
    }

    @Test
    void rejectsARequestWhenARuleRejectsIt() {
        FetchMetadataFilter filter = filterWith(FetchMetadataRuleResult.REJECTED);

        assertEquals(HttpStatus.FORBIDDEN, filter.filterRequest(REQUEST).getStatus());
    }

    @Test
    void rejectsARequestWhenNoRuleCanDecide() {
        FetchMetadataFilter filter = filterWith(FetchMetadataRuleResult.UNKNOWN);

        assertEquals(HttpStatus.FORBIDDEN, filter.filterRequest(REQUEST).getStatus());
    }

    @Test
    void stopsAfterTheFirstDecisiveRule() {
        AtomicBoolean laterRuleCalled = new AtomicBoolean();
        FetchMetadataRule<HttpRequest<?>> allow = request -> FetchMetadataRuleResult.ALLOWED;
        FetchMetadataRule<HttpRequest<?>> laterRule = request -> {
            laterRuleCalled.set(true);
            return FetchMetadataRuleResult.REJECTED;
        };
        FetchMetadataFilter filter = new FetchMetadataFilter(List.of(allow, laterRule));

        assertNull(filter.filterRequest(REQUEST));
        assertFalse(laterRuleCalled.get());
    }

    @Test
    void addsTheFetchMetadataHeadersToVary() {
        MutableHttpResponse<?> response = HttpResponse.ok();

        filterWith(FetchMetadataRuleResult.ALLOWED).filterResponse(response);

        assertEquals(List.of("Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest"),
            response.getHeaders().getAll(HttpHeaders.VARY));
    }

    @Test
    void mergesTheFetchMetadataHeadersWithAnExistingVary() {
        MutableHttpResponse<?> response = HttpResponse.ok()
            .header(HttpHeaders.VARY, "Origin, sec-fetch-site")
            .header(HttpHeaders.VARY, "Accept-Encoding,,");

        filterWith(FetchMetadataRuleResult.ALLOWED).filterResponse(response);

        assertEquals(List.of("Origin, sec-fetch-site, Accept-Encoding, Sec-Fetch-Mode, Sec-Fetch-Dest"),
            response.getHeaders().getAll(HttpHeaders.VARY));
    }

    @Test
    void leavesVaryUnchangedWhenItAlreadyListsTheFetchMetadataHeaders() {
        MutableHttpResponse<?> response = HttpResponse.ok()
            .header(HttpHeaders.VARY, "Sec-Fetch-Dest")
            .header(HttpHeaders.VARY, "Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest");

        filterWith(FetchMetadataRuleResult.ALLOWED).filterResponse(response);

        assertEquals(List.of("Sec-Fetch-Dest", "Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest"),
            response.getHeaders().getAll(HttpHeaders.VARY));
    }

    @Test
    void leavesAWildcardVaryUnchanged() {
        MutableHttpResponse<?> response = HttpResponse.ok().header(HttpHeaders.VARY, "Origin, *");

        filterWith(FetchMetadataRuleResult.ALLOWED).filterResponse(response);

        assertEquals(List.of("Origin, *"), response.getHeaders().getAll(HttpHeaders.VARY));
    }

    private static FetchMetadataFilter filterWith(FetchMetadataRuleResult result) {
        FetchMetadataRule<HttpRequest<?>> rule = request -> result;
        return new FetchMetadataFilter(List.of(rule));
    }
}
