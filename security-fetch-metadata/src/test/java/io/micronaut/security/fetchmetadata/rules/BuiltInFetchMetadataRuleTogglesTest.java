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

import io.micronaut.context.ApplicationContext;
import io.micronaut.core.util.StringUtils;
import io.micronaut.http.Destination;
import io.micronaut.http.HttpHeaders;
import io.micronaut.http.HttpMethod;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.Mode;
import io.micronaut.http.MutableHttpRequest;
import io.micronaut.http.Site;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.runtime.server.EmbeddedServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Each built-in rule toggle changes the outcome of the request that only that rule decides.
 */
class BuiltInFetchMetadataRuleTogglesTest {

    static Stream<Arguments> toggles() {
        return Stream.of(
            Arguments.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_NO_FETCH_METADATA,
                (Supplier<HttpRequest<?>>) () -> HttpRequest.GET("/fetch-metadata")),
            Arguments.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SAME_ORIGIN,
                (Supplier<HttpRequest<?>>) () -> request(HttpMethod.POST, "/fetch-metadata", Site.SAME_ORIGIN, Mode.CORS, Destination.EMPTY)),
            Arguments.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_BROWSER_INITIATED_REQUESTS,
                // a POST navigation, so that the simple navigation rule does not allow it as well
                (Supplier<HttpRequest<?>>) () -> request(HttpMethod.POST, "/fetch-metadata", Site.NONE, Mode.NAVIGATE, Destination.DOCUMENT)),
            Arguments.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SIMPLE_NAVIGATION,
                (Supplier<HttpRequest<?>>) () -> request(HttpMethod.GET, "/fetch-metadata", Site.CROSS_SITE, Mode.NAVIGATE, Destination.DOCUMENT)),
            Arguments.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_CROSS_ORIGIN,
                (Supplier<HttpRequest<?>>) () -> request(HttpMethod.GET, "/fetch-metadata/cors", Site.CROSS_SITE, Mode.CORS, Destination.EMPTY)
                    .header(HttpHeaders.ORIGIN, "https://allowed.example"))
        );
    }

    @ParameterizedTest
    @MethodSource("toggles")
    void disablingARuleRejectsTheRequestOnlyThatRuleAllows(String property, Supplier<HttpRequest<?>> request) {
        assertEquals(HttpStatus.OK, status(Map.of(), request.get()));
        assertEquals(HttpStatus.FORBIDDEN, status(Map.of(property, StringUtils.FALSE), request.get()));
    }

    @Test
    void enablingTheSameSiteRuleAllowsSameSiteRequests() {
        // a new request per server: the client resolves a request's relative URI against its server
        Supplier<HttpRequest<?>> sameSite = () -> request(HttpMethod.GET, "/fetch-metadata", Site.SAME_SITE, Mode.NO_CORS, Destination.IMAGE);

        assertEquals(HttpStatus.FORBIDDEN, status(Map.of(), sameSite.get()));
        assertEquals(HttpStatus.OK, status(Map.of(FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SAME_SITE, StringUtils.TRUE), sameSite.get()));
    }

    @Test
    void disablingEveryRuleRejectsEveryRequest() {
        Map<String, Object> allDisabled = Map.of(
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_NO_FETCH_METADATA, StringUtils.FALSE,
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SAME_ORIGIN, StringUtils.FALSE,
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SAME_SITE, StringUtils.FALSE,
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_BROWSER_INITIATED_REQUESTS, StringUtils.FALSE,
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_SIMPLE_NAVIGATION, StringUtils.FALSE,
            FetchMetadataRulesConfiguration.PROPERTY_ALLOW_CROSS_ORIGIN, StringUtils.FALSE);

        assertEquals(HttpStatus.FORBIDDEN, status(allDisabled, HttpRequest.GET("/fetch-metadata")));
        assertEquals(HttpStatus.FORBIDDEN, status(allDisabled,
            request(HttpMethod.GET, "/fetch-metadata", Site.SAME_ORIGIN, Mode.CORS, Destination.EMPTY)));
    }

    private static HttpStatus status(Map<String, Object> properties, HttpRequest<?> request) {
        try (EmbeddedServer server = ApplicationContext.run(EmbeddedServer.class, properties);
             HttpClient client = server.getApplicationContext().createBean(HttpClient.class, server.getURL())) {
            return client.toBlocking().exchange(request).getStatus();
        } catch (HttpClientResponseException e) {
            return e.getStatus();
        }
    }

    private static MutableHttpRequest<?> request(HttpMethod method, String path, Site site, Mode mode, Destination destination) {
        return HttpRequest.create(method, path)
            .header(HttpHeaders.SEC_FETCH_SITE, site.toString())
            .header(HttpHeaders.SEC_FETCH_MODE, mode.toString())
            .header(HttpHeaders.SEC_FETCH_DEST, destination.toString());
    }
}
